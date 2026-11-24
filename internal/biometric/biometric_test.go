package biometric_test

import (
	"testing"
	"time"

	"hazmatcontrol/internal/biometric"
	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/model"
)

var now = time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)

func eval() *biometric.Evaluator {
	return biometric.NewEvaluator(biometric.DefaultConfig(), clock.NewFake(now))
}

func op() model.OperatorID { return "alice" }

func TestStrongFacePasses(t *testing.T) {
	d := eval().Evaluate(op(), []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.9, Score: 0.93, Liveness: 0.95, Reason: biometric.ReasonOK, At: now,
	}})
	if !d.Verified || d.Mode != "face" {
		t.Fatalf("got %+v", d)
	}
}

// A decent-but-not-strong face alone is refused: 0.75 clears MatchThreshold but
// not StrongScore, and there is no second factor.
func TestWeakFaceAloneRefused(t *testing.T) {
	d := eval().Evaluate(op(), []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.9, Score: 0.75, Liveness: 0.95, Reason: biometric.ReasonOK, At: now,
	}})
	if d.Verified {
		t.Fatalf("weak face alone should not verify: %+v", d)
	}
}

// The same face plus a voice sample fuses to a pass.
func TestFacePlusVoiceFuses(t *testing.T) {
	d := eval().Evaluate(op(), []biometric.Sample{
		{Modality: biometric.ModFace, Quality: 0.9, Score: 0.75, Liveness: 0.95, Reason: biometric.ReasonOK, At: now},
		{Modality: biometric.ModVoice, Quality: 0.85, Score: 0.8, Liveness: 0.9, Reason: biometric.ReasonOK, At: now},
	})
	if !d.Verified || d.Mode != "multimodal" {
		t.Fatalf("got %+v", d)
	}
	if d.Confidence <= 0.75 {
		t.Fatalf("fused confidence should exceed either factor, got %.3f", d.Confidence)
	}
}

// Liveness failure refuses everything, even a strong score.
func TestSpoofHardRefuse(t *testing.T) {
	d := eval().Evaluate(op(), []biometric.Sample{
		{Modality: biometric.ModFace, Quality: 0.9, Score: 0.95, Liveness: 0.9, Reason: biometric.ReasonSpoofSuspected, At: now},
		{Modality: biometric.ModVoice, Quality: 0.9, Score: 0.9, Liveness: 0.9, Reason: biometric.ReasonOK, At: now},
	})
	if d.Verified || d.Mode != "refused" {
		t.Fatalf("spoof must hard-refuse: %+v", d)
	}
}

// Masked face + usable voice is the fallback path.
func TestMaskedFallback(t *testing.T) {
	d := eval().Evaluate(op(), []biometric.Sample{
		{Modality: biometric.ModFace, Quality: 0.2, Reason: biometric.ReasonMasked, At: now},
		{Modality: biometric.ModVoice, Quality: 0.8, Score: 0.86, Liveness: 0.9, Reason: biometric.ReasonOK, At: now},
	})
	if !d.Verified || d.Mode != "fallback" {
		t.Fatalf("got %+v", d)
	}
}

// A sample from a different operator must never count for this operator, even
// if it is a perfect match for that other operator.
func TestOtherOperatorSampleIgnored(t *testing.T) {
	d := eval().Evaluate(op(), []biometric.Sample{{
		Modality: biometric.ModFace, Operator: "bob", Quality: 0.9, Score: 0.99, Liveness: 0.95, Reason: biometric.ReasonOK, At: now,
	}})
	if d.Verified {
		t.Fatalf("bob's sample must not verify alice: %+v", d)
	}
}

// Evidence older than MaxSampleAge is ignored: a saved photo from a previous
// session cannot authenticate now.
func TestStaleSampleIgnored(t *testing.T) {
	d := eval().Evaluate(op(), []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.9, Score: 0.99, Liveness: 0.95, Reason: biometric.ReasonOK,
		At: now.Add(-5 * time.Minute),
	}})
	if d.Verified {
		t.Fatalf("stale sample must not verify: %+v", d)
	}
}

// No capture at all is a refusal with a documented reason.
func TestNoEvidence(t *testing.T) {
	d := eval().Evaluate(op(), nil)
	if d.Verified {
		t.Fatal("no evidence must not verify")
	}
	if len(d.Reasons) != 0 && d.Detail == "" {
		t.Fatal("refusal must carry a detail")
	}
}
