// Package weigh reconciles the quantity an operator *claims* to have removed
// against what the platform scale actually *measured*, and against the issue
// authorisation.
//
// The hard parts this package addresses:
//
//   - Time gap and drift. A scale reading taken minutes after removal, or from a
//     scale with a stale tare, is not evidence of a specific removal. Bind every
//     reading to a session, a container and a time window, and require a stable
//     reading (several samples within tolerance) rather than a single value.
//
//   - Container vs. net. A full canister weighs a lot; what matters is the
//     delta. The scale must be calibrated (tare) for the container in this
//     session, and a tare older than MaxTareAge is rejected.
//
//   - Tolerance by hazard. Highly-toxic products need a tight tolerance and a
//     hard stop; general products can be reconciled with a note.
//
// The package is pure logic: it takes readings and returns a verdict with a
// documented reason, which the session layer writes to the ledger.
package weigh

import (
	"fmt"
	"time"

	"hazmatcontrol/internal/clock"
)

// Reading is one sample from the platform scale.
type Reading struct {
	ContainerID string
	Grams       float64
	Stable      bool
	At          time.Time
	ScaleID     string
}

// Tare is a container's empty weight, established when the container was placed
// and zeroed in this session.
type Tare struct {
	ContainerID string
	Grams       float64
	At          time.Time
	ScaleID     string
}

// Verdict classifies a reconciliation.
type Verdict string

const (
	// VerdictMatched: measured within tolerance of claimed and authorised.
	VerdictMatched Verdict = "matched"
	// VerdictUnder: measured less than claimed beyond tolerance (operator may
	// have over-declared, or a previous removal went unrecorded).
	VerdictUnder Verdict = "shortfall"
	// VerdictOver: measured more than claimed beyond tolerance (undeclared
	// material — a serious finding for highly toxic products).
	VerdictOver Verdict = "overage"
	// VerdictUnstable: no stable reading; cannot reconcile automatically.
	VerdictUnstable Verdict = "unstable"
	// VerdictStaleTare: tare too old or from another scale.
	VerdictStaleTare Verdict = "stale_tare"
)

// Config is the reconciliation policy.
type Config struct {
	// StableSamples is how many consecutive stable readings within
	// StableSpreadGrams are required.
	StableSamples     int
	StableSpreadGrams float64
	// MaxReadingAge bounds how old a reading may be at evaluation time.
	MaxReadingAge time.Duration
	// MaxTareAge bounds how old the container tare may be.
	MaxTareAge time.Duration
	// Tolerance is the allowed absolute deviation by hazard class.
	Tolerance map[string]Tolerance
}

// Tolerance is a per-hazard absolute and relative allowance.
type Tolerance struct {
	AbsGrams float64
	RelPct   float64
}

func DefaultConfig() Config {
	return Config{
		StableSamples:     5,
		StableSpreadGrams: 2.0,
		MaxReadingAge:     10 * time.Minute,
		MaxTareAge:        45 * time.Minute,
		Tolerance: map[string]Tolerance{
			"highly_toxic": {AbsGrams: 2.0, RelPct: 0.5},
			"general":      {AbsGrams: 20.0, RelPct: 2.0},
		},
	}
}

// Result is the outcome of reconciling one removal.
type Result struct {
	Verdict      Verdict
	ClaimedGrams float64
	RemovedGrams float64
	AllowedGrams float64
	DeviationG   float64
	Detail       string
}

// Reconciler evaluates readings.
type Reconciler struct {
	cfg Config
	clk clock.Clock
}

func NewReconciler(cfg Config, clk clock.Clock) *Reconciler {
	return &Reconciler{cfg: cfg, clk: clk}
}

// stableValue returns the median of the trailing stable run if one exists.
func (r *Reconciler) stableValue(readings []Reading) (float64, bool) {
	if len(readings) < r.cfg.StableSamples {
		return 0, false
	}
	tail := readings[len(readings)-r.cfg.StableSamples:]
	lo, hi := tail[0].Grams, tail[0].Grams
	for _, rd := range tail {
		if !rd.Stable {
			return 0, false
		}
		if rd.Grams < lo {
			lo = rd.Grams
		}
		if rd.Grams > hi {
			hi = rd.Grams
		}
	}
	if hi-lo > r.cfg.StableSpreadGrams {
		return 0, false
	}
	// Median is robust to a single outlier at the edge of the spread.
	g := make([]float64, len(tail))
	for i, rd := range tail {
		g[i] = rd.Grams
	}
	return median(g), true
}

// Reconcile compares a claim and the authorised amount against scale readings.
//
// before is the stable gross reading taken before removal, after is the stable
// gross reading taken after. tare is the container's empty weight. claimed is
// what the operator entered; authorised is what the permit allows.
func (r *Reconciler) Reconcile(hazard string, tare Tare, before, after []Reading, claimed, authorised float64) Result {
	tol := r.cfg.Tolerance[hazard]
	if tol == (Tolerance{}) {
		tol = r.cfg.Tolerance["general"]
	}
	now := r.clk.Now()
	res := Result{ClaimedGrams: claimed}

	if now.Sub(tare.At) > r.cfg.MaxTareAge {
		res.Verdict = VerdictStaleTare
		res.Detail = fmt.Sprintf("tare for %s is %s old (max %s)", tare.ContainerID, now.Sub(tare.At).Round(time.Second), r.cfg.MaxTareAge)
		return res
	}
	for _, set := range [][]Reading{before, after} {
		for _, rd := range set {
			if now.Sub(rd.At) > r.cfg.MaxReadingAge {
				res.Verdict = VerdictUnstable
				res.Detail = fmt.Sprintf("reading from %s is %s old (max %s)", rd.ScaleID, now.Sub(rd.At).Round(time.Second), r.cfg.MaxReadingAge)
				return res
			}
			if rd.ContainerID != tare.ContainerID {
				res.Verdict = VerdictUnstable
				res.Detail = fmt.Sprintf("reading for container %s but tare is for %s", rd.ContainerID, tare.ContainerID)
				return res
			}
		}
	}
	grossBefore, ok1 := r.stableValue(before)
	grossAfter, ok2 := r.stableValue(after)
	if !ok1 || !ok2 {
		res.Verdict = VerdictUnstable
		res.Detail = "no stable weighing run before/after removal"
		return res
	}
	removed := (grossBefore - grossAfter)
	if removed < 0 {
		// Material was added back, or the container changed. Never accept.
		res.Verdict = VerdictUnstable
		res.Detail = fmt.Sprintf("gross weight increased by %.1fg during removal; container swap or scale fault", -removed)
		return res
	}
	res.RemovedGrams = removed
	// Authorised amount is also the ceiling: over the permit is an overage
	// regardless of the claim.
	allowed := tol.AbsGrams + tol.RelPct/100*authorised
	res.AllowedGrams = allowed
	res.DeviationG = removed - claimed

	// Over-age check runs against both the claim and the authorisation.
	overClaim := removed-claimed > allowed
	overAuth := removed-authorised > allowed
	switch {
	case overClaim || overAuth:
		res.Verdict = VerdictOver
		ref := "claim"
		limit := claimed
		if overAuth {
			ref = "authorisation"
			limit = authorised
		}
		res.Detail = fmt.Sprintf("removed %.1fg exceeds %s %.1fg by %.1fg (allowed %.1fg)", removed, ref, limit, removed-limit, allowed)
	case claimed-removed > allowed:
		res.Verdict = VerdictUnder
		res.Detail = fmt.Sprintf("claimed %.1fg but measured %.1fg (shortfall %.1fg, allowed %.1fg)", claimed, removed, claimed-removed, allowed)
	default:
		res.Verdict = VerdictMatched
		res.Detail = fmt.Sprintf("measured %.1fg vs claimed %.1fg (deviation %.1fg within %.1fg)", removed, claimed, removed-claimed, allowed)
	}
	return res
}

func median(v []float64) float64 {
	// Insertion sort; arrays here are tiny (StableSamples).
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}
