package weigh_test

import (
	"testing"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/weigh"
)

var t0 = time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)

func run(container string, gross float64, base time.Time) []weigh.Reading {
	out := make([]weigh.Reading, 5)
	for i := range out {
		out[i] = weigh.Reading{ContainerID: container, Grams: gross, Stable: true, At: base, ScaleID: "s1"}
	}
	return out
}

func rec(clk clock.Clock) *weigh.Reconciler {
	return weigh.NewReconciler(weigh.DefaultConfig(), clk)
}

func TestMatched(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0, ScaleID: "s1"}
	res := rec(clk).Reconcile("highly_toxic", tare, run("c", 12000, t0), run("c", 11980, t0), 20, 50)
	if res.Verdict != weigh.VerdictMatched {
		t.Fatalf("verdict = %s: %s", res.Verdict, res.Detail)
	}
	if res.RemovedGrams != 20 {
		t.Fatalf("removed = %.1f, want 20", res.RemovedGrams)
	}
}

// Measured well above the claim AND above authorisation: overage.
func TestOverage(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0, ScaleID: "s1"}
	res := rec(clk).Reconcile("highly_toxic", tare, run("c", 12000, t0), run("c", 11930, t0), 30, 30)
	if res.Verdict != weigh.VerdictOver {
		t.Fatalf("verdict = %s, want overage: %s", res.Verdict, res.Detail)
	}
}

// Measured below the claim beyond tolerance: shortfall.
func TestShortfall(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0, ScaleID: "s1"}
	res := rec(clk).Reconcile("highly_toxic", tare, run("c", 12000, t0), run("c", 11990, t0), 40, 100)
	if res.Verdict != weigh.VerdictUnder {
		t.Fatalf("verdict = %s, want shortfall: %s", res.Verdict, res.Detail)
	}
}

// Two grams on a general product is within the wide tolerance.
func TestGeneralToleranceWider(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0, ScaleID: "s1"}
	res := rec(clk).Reconcile("general", tare, run("c", 12000, t0), run("c", 11980, t0), 21, 500)
	if res.Verdict != weigh.VerdictMatched {
		t.Fatalf("general product 1g deviation should match: %s", res.Verdict)
	}
	// The same 1g deviation on a highly toxic product with a small authorisation
	// is still within 2g abs tolerance, so also matched; but 5g is not.
	res = rec(clk).Reconcile("highly_toxic", tare, run("c", 12000, t0), run("c", 11975, t0), 20, 30)
	if res.Verdict == weigh.VerdictMatched {
		t.Fatalf("5g deviation should not match highly toxic: %s", res.Detail)
	}
}

// Unstable run (spread too wide) is refused.
func TestUnstableSpread(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0, ScaleID: "s1"}
	after := run("c", 11980, t0)
	after[2].Grams = 11990 // 10g outlier, beyond the 2g stable spread
	res := rec(clk).Reconcile("general", tare, run("c", 12000, t0), after, 20, 50)
	if res.Verdict != weigh.VerdictUnstable {
		t.Fatalf("verdict = %s, want unstable", res.Verdict)
	}
}

// Gross weight increasing means a container swap or fault, never a valid removal.
func TestGrossIncreaseRefused(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0, ScaleID: "s1"}
	res := rec(clk).Reconcile("general", tare, run("c", 11000, t0), run("c", 12000, t0), 20, 50)
	if res.Verdict != weigh.VerdictUnstable {
		t.Fatalf("verdict = %s, want unstable on gross increase", res.Verdict)
	}
}

// Stale tare is refused before any math runs.
func TestStaleTare(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0.Add(-2 * time.Hour), ScaleID: "s1"}
	res := rec(clk).Reconcile("general", tare, run("c", 12000, t0), run("c", 11980, t0), 20, 50)
	if res.Verdict != weigh.VerdictStaleTare {
		t.Fatalf("verdict = %s, want stale_tare", res.Verdict)
	}
}

// A reading from a different container than the tare is refused: this catches a
// drum swap under the scale.
func TestContainerMismatch(t *testing.T) {
	clk := clock.NewFake(t0)
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0, ScaleID: "s1"}
	res := rec(clk).Reconcile("general", tare, run("other", 12000, t0), run("other", 11980, t0), 20, 50)
	if res.Verdict != weigh.VerdictUnstable {
		t.Fatalf("verdict = %s, want unstable on container mismatch", res.Verdict)
	}
}

// Readings older than the max age are refused, closing the "weigh later" gap.
func TestStaleReadings(t *testing.T) {
	clk := clock.NewFake(t0.Add(1 * time.Hour))
	tare := weigh.Tare{ContainerID: "c", Grams: 500, At: t0.Add(59 * time.Minute), ScaleID: "s1"}
	res := rec(clk).Reconcile("general", tare, run("c", 12000, t0), run("c", 11980, t0), 20, 50)
	if res.Verdict != weigh.VerdictUnstable {
		t.Fatalf("verdict = %s, want unstable on stale readings", res.Verdict)
	}
}
