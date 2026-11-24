package access_test

import (
	"errors"
	"testing"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/model"
)

type fakePC struct {
	live   bool
	detail string
}

func (f *fakePC) BothLive(a, b model.OperatorID) (bool, string) { return f.live, f.detail }

type fakeDist struct {
	valid map[string]bool
}

func (f *fakeDist) Verify(session string, op model.OperatorID, proof string) bool {
	return f.valid[string(op)+"|"+proof]
}

type fakeAct struct {
	open map[access.Slot]bool
}

func newFakeAct() *fakeAct                           { return &fakeAct{open: map[access.Slot]bool{}} }
func (f *fakeAct) Open(s access.Slot) error          { f.open[s] = true; return nil }
func (f *fakeAct) Close(s access.Slot) error         { f.open[s] = false; return nil }
func (f *fakeAct) State(s access.Slot) (bool, error) { return f.open[s], nil }

func setup(pc *fakePC) (*access.DualLock, *fakeAct, *fakeDist, *clock.Fake) {
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	act := newFakeAct()
	dist := &fakeDist{valid: map[string]bool{}}
	cfg := access.Config{UnlockWindow: 30 * time.Second, RelockWindow: 5 * time.Minute, RequireDistinctness: false}
	return access.New(cfg, clk, act, pc, dist), act, dist, clk
}

func TestDistinctnessRequiredWhenFlagged(t *testing.T) {
	pc := &fakePC{live: true}
	lock, act, dist, _ := setup(pc)
	if err := lock.Arm("s1", "alice", "bob"); err != nil {
		t.Fatal(err)
	}
	lock.RequireDistinctnessFor("s1")
	// No proof supplied: refused.
	err := lock.Present(access.SlotA, access.Credential{Operator: "alice"})
	if !errors.Is(err, access.ErrNotDistinct) {
		t.Fatalf("want distinctness error, got %v", err)
	}
	if act.open[access.SlotA] {
		t.Fatal("actuator opened without distinctness proof")
	}
	// Supply a valid one-time proof; accepted.
	dist.valid["alice|p1"] = true
	if err := lock.Present(access.SlotA, access.Credential{Operator: "alice", DistinctnessProof: "p1"}); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
}

// Presence must be re-checked at unlock even if it held at arm time.
func TestPresenceRecheckedAtUnlock(t *testing.T) {
	pc := &fakePC{live: true}
	lock, act, _, _ := setup(pc)
	lock.Arm("s1", "alice", "bob")
	pc.live = false // bob walked off before anyone presented
	err := lock.Present(access.SlotA, access.Credential{Operator: "alice"})
	if !errors.Is(err, access.ErrPresenceLost) {
		t.Fatalf("want presence lost, got %v", err)
	}
	if act.open[access.SlotA] {
		t.Fatal("opened without presence")
	}
}

// Touch re-checks presence for mid-session progress.
func TestTouchRechecksPresence(t *testing.T) {
	pc := &fakePC{live: true}
	lock, _, _, _ := setup(pc)
	lock.Arm("s1", "alice", "bob")
	if err := lock.Touch(); err != nil {
		t.Fatal(err)
	}
	pc.live = false
	if err := lock.Touch(); !errors.Is(err, access.ErrPresenceLost) {
		t.Fatalf("want presence lost on touch, got %v", err)
	}
}

// Arming closes locks that were unexpectedly open (fail-closed).
func TestArmClosesOpenLocks(t *testing.T) {
	pc := &fakePC{live: true}
	lock, act, _, _ := setup(pc)
	act.open[access.SlotA] = true
	act.open[access.SlotB] = true
	if err := lock.Arm("s1", "alice", "bob"); err != nil {
		t.Fatal(err)
	}
	if act.open[access.SlotA] || act.open[access.SlotB] {
		t.Fatal("arm did not fail closed")
	}
}

// Watchdog force-relocks an idle open session.
func TestWatchdogRelocks(t *testing.T) {
	pc := &fakePC{live: true}
	lock, act, _, clk := setup(pc)
	lock.Arm("s1", "alice", "bob")
	lock.Present(access.SlotA, access.Credential{Operator: "alice"})
	lock.Present(access.SlotB, access.Credential{Operator: "bob"})
	if !act.open[access.SlotA] || !act.open[access.SlotB] {
		t.Fatal("both should be open")
	}
	clk.Advance(6 * time.Minute) // beyond RelockWindow 5m
	relocked, err := lock.Watchdog()
	if err != nil {
		t.Fatal(err)
	}
	if !relocked {
		t.Fatal("watchdog did not relock an idle session")
	}
	if act.open[access.SlotA] || act.open[access.SlotB] {
		t.Fatal("locks still open after watchdog")
	}
}

// Two distinct operators are required to arm at all.
func TestArmNeedsDistinctOperators(t *testing.T) {
	lock, _, _, _ := setup(&fakePC{live: true})
	if err := lock.Arm("s1", "alice", "alice"); err == nil {
		t.Fatal("arming with one operator twice must fail")
	}
}
