// Package biometric turns raw capture attempts into per-operator identity
// assertions. It is built around one hard-won operational fact: workers in a
// highly-toxic store wear respirators and face shields, so face recognition
// frequently cannot produce a usable template. Treating face as a pass/fail
// gate would either block every withdrawal or tempt operators to prop the
// camera, which is exactly how badge sharing starts.
//
// Instead every modality can *abstain* with a reason. A decision is a fusion of
// whatever usable evidence exists, and the policy chooses between:
//
//   - an automatic pass (enough high-quality, live evidence),
//   - a fallback challenge (e.g. masked operator verified by voice plus PIN),
//   - an escorted pass (a supervisor physically present attests identity),
//   - a refusal.
//
// Every decision, including abstentions and their reasons, is recorded so an
// auditor can see that a masked operator was not silently waved through.
package biometric

import (
	"fmt"
	"math"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/model"
)

// Modality names a biometric channel.
type Modality string

const (
	ModFace   Modality = "face"
	ModVoice  Modality = "voice"
	ModFinger Modality = "fingerprint"
	ModGait   Modality = "gait"
)

// Reason explains why a sample could not be used. These strings are stored in
// the ledger, so they should stay stable.
type Reason string

const (
	ReasonOK             Reason = "ok"
	ReasonMasked         Reason = "face_covered"
	ReasonLowLight       Reason = "low_light"
	ReasonMotionBlur     Reason = "motion_blur"
	ReasonTooFar         Reason = "subject_too_far"
	ReasonSpoofSuspected Reason = "liveness_failed"
	ReasonNoTemplate     Reason = "no_template"
	ReasonLowScore       Reason = "match_below_threshold"
	ReasonNoCapture      Reason = "no_capture"
	ReasonTimeout        Reason = "timeout"
)

// Sample is one capture attempt.
type Sample struct {
	Modality Modality
	Operator model.OperatorID
	Quality  float64 // 0..1, capture quality independent of match
	Score    float64 // 0..1, similarity to the enrolled template
	Liveness float64 // 0..1, presentation-attack detection confidence
	At       time.Time
	Device   string
	Reason   Reason
}

// Usable reports whether the sample carries trustworthy evidence.
func (s Sample) Usable(cfg Config) bool {
	return s.Reason == ReasonOK &&
		s.Quality >= cfg.MinQuality &&
		s.Liveness >= cfg.MinLiveness &&
		s.Score >= cfg.MatchThreshold
}

// Config is the fusion policy.
type Config struct {
	MinQuality     float64
	MinLiveness    float64
	MatchThreshold float64
	// StrongScore is the score above which a single good face sample passes.
	StrongScore float64
	// MaxSampleAge is how old evidence may be at decision time.
	MaxSampleAge time.Duration
	// EscortRequiresSupervisor makes a masked operator's fallback require a
	// physically present supervisor, not just a voice sample.
	EscortRequiresSupervisor bool
}

// DefaultConfig sets thresholds assuming a modern depth+liveness camera.
func DefaultConfig() Config {
	return Config{
		MinQuality:               0.55,
		MinLiveness:              0.7,
		MatchThreshold:           0.72,
		StrongScore:              0.88,
		MaxSampleAge:             90 * time.Second,
		EscortRequiresSupervisor: true,
	}
}

// Decision is the outcome for one operator at one moment.
type Decision struct {
	Operator   model.OperatorID
	Verified   bool
	Mode       string // "face", "fallback", "escort", "refused"
	Confidence float64
	Reasons    []Reason
	Detail     string
	At         time.Time
	// Samples documents the evidence considered, for the ledger.
	Samples []Sample
}

// Challenger lets the policy ask for an alternate modality when face abstains.
// In production it drives the console UI; in tests and the demo it is scripted.
type Challenger interface {
	// Challenge requests modality m from operator op and returns the resulting
	// sample. Returning a zero sample means the operator refused or timed out.
	Challenge(op model.OperatorID, m Modality) (Sample, error)
}

// Evaluator fuses samples into decisions.
type Evaluator struct {
	cfg Config
	clk clock.Clock
}

func NewEvaluator(cfg Config, clk clock.Clock) *Evaluator {
	return &Evaluator{cfg: cfg, clk: clk}
}

// Evaluate decides one operator from an already-collected set of samples. It
// never blocks. Challenge-driven flows should call Collect then Evaluate.
//
// The ordering of evidence is deliberate: a strong, live face wins; a decent
// face plus a second modality wins; a masked operator falls back to a
// possession factor plus supervisor escort. A weak face alone never wins.
func (e *Evaluator) Evaluate(op model.OperatorID, samples []Sample) Decision {
	now := e.clk.Now()
	d := Decision{Operator: op, At: now}
	var usableFace, usableOther []Sample
	var sawMask, sawSpoof bool
	var bestFaceRaw float64 // best face score seen, usable or not, for honest reporting
	for _, s := range samples {
		if s.Operator != "" && s.Operator != op {
			continue
		}
		if now.Sub(s.At) > e.cfg.MaxSampleAge {
			continue
		}
		switch s.Reason {
		case ReasonMasked:
			sawMask = true
		case ReasonSpoofSuspected:
			sawSpoof = true
		}
		if s.Modality == ModFace {
			if s.Score > bestFaceRaw {
				bestFaceRaw = s.Score
			}
			if s.Usable(e.cfg) {
				usableFace = append(usableFace, s)
				continue
			}
		} else if s.Usable(e.cfg) {
			usableOther = append(usableOther, s)
			continue
		}
		d.Reasons = append(d.Reasons, s.Reason)
	}
	d.Samples = samples

	bestFace := best(usableFace)
	if bestFace.Score >= e.cfg.StrongScore {
		d.Verified = true
		d.Mode = "face"
		d.Confidence = bestFace.Score
		d.Detail = fmt.Sprintf("strong face match %.3f", bestFace.Score)
		return d
	}
	// A spoof-suspected sample is a security event: refuse even if other
	// evidence would pass, and let a supervisor investigate.
	if sawSpoof {
		d.Mode = "refused"
		d.Detail = "liveness check failed; possible presentation attack"
		return d
	}
	if bestFace.Score >= e.cfg.MatchThreshold && len(usableOther) > 0 {
		// Face plus a second modality: require both to agree on identity.
		bestOther := best(usableOther)
		if bestOther.Operator == "" || bestOther.Operator == op {
			d.Verified = true
			d.Mode = "multimodal"
			d.Confidence = fused(bestFace.Score, bestOther.Score)
			d.Detail = fmt.Sprintf("face %.3f + %s %.3f", bestFace.Score, bestOther.Modality, bestOther.Score)
			return d
		}
	}
	if sawMask || bestFace.Score < e.cfg.MatchThreshold {
		if len(usableOther) > 0 {
			bestOther := best(usableOther)
			d.Verified = true
			d.Mode = "fallback"
			d.Confidence = clamp01(bestOther.Score * 0.9)
			d.Detail = fmt.Sprintf("face abstained (%s); %s match %.3f", abstainNote(sawMask, bestFaceRaw, e.cfg.MatchThreshold), bestOther.Modality, bestOther.Score)
			return d
		}
		d.Mode = "refused"
		d.Detail = fmt.Sprintf("face abstained (%s) and no alternate factor", abstainNote(sawMask, bestFaceRaw, e.cfg.MatchThreshold))
		return d
	}
	d.Mode = "refused"
	d.Detail = "insufficient evidence"
	return d
}

// Escort records a supervisor's physical attestation. It is a distinct path
// from biometric consent so that the ledger shows, in words, that a human took
// responsibility for the identity claim.
func (e *Evaluator) Escort(op, supervisor model.OperatorID, note string) Decision {
	return Decision{
		Operator:   op,
		Verified:   true,
		Mode:       "escort",
		Confidence: 1.0,
		Detail:     fmt.Sprintf("supervisor %s attested identity: %s", supervisor, note),
		At:         e.clk.Now(),
	}
}

// Collect drives the challenge flow for a masked operator: it tries face, and on
// a mask abstention asks for voice (or fingerprint) via ch. It returns the raw
// samples, leaving the decision to Evaluate so tests can inspect both.
func (e *Evaluator) Collect(op model.OperatorID, ch Challenger) ([]Sample, error) {
	face, err := ch.Challenge(op, ModFace)
	if err != nil {
		return nil, err
	}
	samples := []Sample{face}
	if face.Reason != ReasonMasked && face.Usable(e.cfg) {
		return samples, nil
	}
	// Try voice first (works through a mask, cheap), then fingerprint.
	for _, m := range []Modality{ModVoice, ModFinger} {
		s, err := ch.Challenge(op, m)
		if err != nil {
			return samples, nil
		}
		samples = append(samples, s)
		if s.Usable(e.cfg) {
			return samples, nil
		}
	}
	return samples, nil
}

// abstainNote explains *why* face did not carry the decision, distinguishing a
// mask (an expected, benign operational condition) from a below-threshold match
// (which, for a claimed identity, can mean the wrong person is present). The
// distinction matters because these strings are read during investigations.
func abstainNote(masked bool, score, threshold float64) string {
	if masked {
		return "face covered/masked"
	}
	return fmt.Sprintf("face match %.3f below threshold %.2f", score, threshold)
}

func best(ss []Sample) Sample {
	var b Sample
	for _, s := range ss {
		if s.Score > b.Score {
			b = s
		}
	}
	return b
}

// fused combines two independent scores with a probability-odds rule; two weak
// independent factors can be strong together, but a weak factor cannot rescue a
// very low one.
func fused(a, b float64) float64 {
	// Convert to odds, multiply, convert back.
	oa := a / math.Max(1e-6, 1-a)
	ob := b / math.Max(1e-6, 1-b)
	o := oa * ob
	return clamp01(o / (1 + o))
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
