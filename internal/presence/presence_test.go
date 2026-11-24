package presence_test

import (
	"testing"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/presence"
)

// scriptedFobs feeds two fob series into a tracker.
func scriptedFobs(t *testing.T, series []([2]int), step time.Duration) (*presence.Tracker, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	if err := tr.BindFob("alice", "fa", "a"); err != nil {
		t.Fatal(err)
	}
	if err := tr.BindFob("bob", "fb", "b"); err != nil {
		t.Fatal(err)
	}
	var ca, cb uint64
	for _, v := range series {
		ca++
		cb++
		tr.Observe(presence.Observation{FobID: "fa", RSSI: v[0], Counter: ca, OnBody: true, At: clk.Now()})
		tr.Observe(presence.Observation{FobID: "fb", RSSI: v[1], Counter: cb, OnBody: true, At: clk.Now()})
		clk.Advance(step)
	}
	return tr, clk
}

// Two fobs riding on one torso shadow each other: their RSSI series move
// together. This must be flagged as a same-body suspicion so the access layer
// can demand a distinctness proof.
func TestSameBodyFobsAreCorrelated(t *testing.T) {
	var series [][2]int
	for i := 0; i < 20; i++ {
		v := -50 - (i % 4) // shared movement
		series = append(series, [2]int{v, v + 1})
	}
	tr, _ := scriptedFobs(t, series, time.Second)
	cp := tr.CoPresence(model.OperatorID("alice"), model.OperatorID("bob"))
	if !cp.SameBody {
		t.Fatalf("expected same-body flag, got r=%.3f", cp.Suspicion)
	}
	if cp.Suspicion < 0.9 {
		t.Fatalf("correlation should be near 1 for shared movement, got %.3f", cp.Suspicion)
	}
}

// Two people standing at the cabinet independently: their RSSI series drift
// apart (different bodies, different multipath). They must NOT be flagged, or
// every legitimate withdrawal would trigger a false challenge.
func TestSeparateBodiesNotCorrelated(t *testing.T) {
	var series [][2]int
	// Deterministic but anti-correlated / independent-looking wander.
	a := []int{-50, -53, -49, -55, -51, -54, -48, -52, -56, -50, -53, -49, -55, -51, -54, -48, -52, -56}
	b := []int{-52, -49, -54, -50, -55, -51, -56, -48, -53, -55, -50, -54, -49, -56, -52, -51, -55, -48}
	for i := range a {
		series = append(series, [2]int{a[i], b[i]})
	}
	tr, _ := scriptedFobs(t, series, time.Second)
	cp := tr.CoPresence(model.OperatorID("alice"), model.OperatorID("bob"))
	if cp.SameBody {
		t.Fatalf("independent bodies wrongly flagged, r=%.3f", cp.Suspicion)
	}
	if !cp.OK {
		t.Fatalf("both should still be present: %s", cp.Reason)
	}
}

// Presence must lapse when heartbeats stop, and report why.
func TestPresenceLeaseExpires(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	if err := tr.BindFob("alice", "fa", "a"); err != nil {
		t.Fatal(err)
	}
	tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 1, OnBody: true, At: clk.Now()})
	if p := tr.Status("alice"); !p.Live {
		t.Fatalf("alice should be live immediately: %s", p.Reason)
	}
	clk.Advance(presence.DefaultConfig().MaxGap + time.Second)
	p := tr.Status("alice")
	if p.Live {
		t.Fatal("alice should have lapsed after MaxGap")
	}
	if p.Reason == "" {
		t.Fatal("lapse must carry a reason")
	}
}

// A fob reported off-body is not presence, even with a strong signal: the fob
// was put down on the shelf.
func TestOffBodyFobNotPresence(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	tr.BindFob("alice", "fa", "a")
	tr.Observe(presence.Observation{FobID: "fa", RSSI: -40, Counter: 1, OnBody: false, At: clk.Now()})
	if p := tr.Status("alice"); p.Live {
		t.Fatal("off-body fob must not count as presence")
	}
}

// Replayed advertisements (older counter) are rejected, so a recording of a
// colleague's fob traffic cannot keep a ghost lease alive.
func TestReplayRejected(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	tr.BindFob("alice", "fa", "a")
	if err := tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 10, OnBody: true, At: clk.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 5, OnBody: true, At: clk.Now()}); err == nil {
		t.Fatal("stale counter should be rejected as replay")
	}
}

// Tamper is terminal for a fob until re-provisioned.
func TestTamperLapsesAndSticks(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	tr.BindFob("alice", "fa", "a")
	tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 1, OnBody: true, At: clk.Now()})
	tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 2, OnBody: true, Tampered: true, At: clk.Now()})
	if p := tr.Status("alice"); p.Live {
		t.Fatal("tampered fob must not be live")
	}
	if err := tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 3, OnBody: true, At: clk.Now()}); err == nil {
		t.Fatal("tampered fob must stay untrusted")
	}
}

// A fob with a wildly future timestamp must not extend a lease.
func TestFutureTimestampClamped(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	tr.BindFob("alice", "fa", "a")
	tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 1, OnBody: true, At: clk.Now()})
	// A forged observation claiming to be an hour in the future.
	tr.Observe(presence.Observation{FobID: "fa", RSSI: -50, Counter: 2, OnBody: true, At: clk.Now().Add(time.Hour)})
	clk.Advance(presence.DefaultConfig().MaxGap + time.Second)
	if p := tr.Status("alice"); p.Live {
		t.Fatal("future-dated observation must not keep the lease alive")
	}
}
