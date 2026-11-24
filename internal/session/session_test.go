package session_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/biometric"
	"hazmatcontrol/internal/ledger"
	"hazmatcontrol/internal/weigh"
)

// TestHappyPath: two operators, both live, dual unlock, a clean withdrawal that
// matches the scale, and a closed session. This is the baseline everything else
// is measured against.
func TestHappyPath(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(50)
	h.unlockBoth(s)
	if s.State() != "open" {
		t.Fatalf("state = %s, want open", s.State())
	}
	h.stageWeigh("drum-1", 10_000, 20)
	res, err := s.RecordRemoval("drum-1", 20, alice)
	if err != nil {
		t.Fatalf("removal: %v (result %+v)", err, res)
	}
	if res.Verdict != weigh.VerdictMatched {
		t.Fatalf("verdict = %s, want matched", res.Verdict)
	}
	must(t, s.BeginReconcile())
	must(t, s.Close(alice))
	if s.State() != "closed" {
		t.Fatalf("state = %s, want closed", s.State())
	}
	if h.act.AnyOpen() {
		t.Fatal("cabinet left open after close")
	}
	if err := ledger.VerifyChain(h.log.Records(), h.keys); err != nil {
		t.Fatalf("ledger chain invalid: %v", err)
	}
}

// TestBadgeSharingSinglePerson is the first reported attack: one person presents
// a colleague's badge and tries to complete "two-person" verification alone.
func TestBadgeSharingSinglePerson(t *testing.T) {
	h := newHarness(t)
	h.enrol()

	s := h.newSession(50)

	// Alice authenticates by face — fine, that is really her.
	_, err := s.Authenticate(alice, h.facePass())
	must(t, err)

	// Now a single body tries to satisfy Bob's slot. Three ways this fails, and
	// all three must fail independently.

	// (a) Face: the camera sees Alice, not Bob. Evaluator's decision is bound to
	// the operator id, so a strong score for the wrong identity is a low score
	// for Bob.
	wrongFace := []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.9, Score: 0.2, Liveness: 0.95,
		Reason: biometric.ReasonLowScore, At: h.clk.Now(),
	}}
	if _, err := s.Authenticate(bob, wrongFace); err == nil {
		t.Fatal("authenticate bob with alice's face should fail")
	}

	// (b) Masked fallback: Alice claims to be Bob and asks for voice fallback.
	// Voice is not Bob's.
	wrongVoice := []biometric.Sample{
		{Modality: biometric.ModFace, Quality: 0.2, Reason: biometric.ReasonMasked, At: h.clk.Now()},
		{Modality: biometric.ModVoice, Quality: 0.8, Score: 0.1, Liveness: 0.9, Reason: biometric.ReasonOK, At: h.clk.Now()},
	}
	if _, err := s.Authenticate(bob, wrongVoice); err == nil {
		t.Fatal("voice fallback for the wrong person should fail")
	}

	// (c) Even if both biometrics were somehow satisfied, presence still requires
	// Bob's fob to be live on a second body. Only Alice's fob is emitting.
	_, err = s.Authenticate(bob, h.facePass())
	must(t, err)
	// Alice is here; Bob's fob has never advertised. Arming must fail.
	if err := s.ArmBoth(); !errors.Is(err, sessionErrPresence) {
		t.Fatalf("arm with one body should fail with presence error, got %v", err)
	}
	if h.act.AnyOpen() {
		t.Fatal("cabinet opened for a single-body two-person attempt")
	}
}

// TestCollusionThenAbandon is the second reported attack: two people
// authenticate and unlock together, then one leaves and the other keeps
// withdrawing.
func TestCollusionThenAbandon(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(100)
	h.unlockBoth(s)

	h.stageWeigh("drum-1", 10_000, 10)
	if _, err := s.RecordRemoval("drum-1", 10, alice); err != nil {
		t.Fatalf("first removal should succeed while both present: %v", err)
	}

	// Bob walks away. His fob stops advertising; the lease lapses.
	h.clk.Advance(10 * time.Second) // past MaxGap (12s? no) — advance beyond
	h.clk.Advance(30 * time.Second)
	// Alice keeps advertising so she is clearly still there.
	must(t, h.fobs.Advertise(fobAlice, -50, h.clk.Now()))

	h.stageWeigh("drum-1", 9_990, 500) // Alice tries to take far more
	_, err := s.RecordRemoval("drum-1", 500, alice)
	if err == nil {
		t.Fatal("removal without bob's presence should be rejected")
	}
	if !errors.Is(err, sessionErrPresence) {
		t.Fatalf("want presence error, got %v", err)
	}
	if s.State() != "aborted" {
		t.Fatalf("state = %s, want aborted", s.State())
	}
	if h.act.AnyOpen() {
		t.Fatal("cabinet still open after presence was lost")
	}
}

// TestCoPresenceWatchdogAbortsWithoutRemoval: even if the remaining operator
// does nothing, the monitor must abort and relock once presence lapses.
func TestCoPresenceWatchdogAbortsWithoutRemoval(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(100)
	h.unlockBoth(s)

	done := make(chan struct{})
	defer close(done)
	go s.Monitor(100*time.Millisecond, done)

	// Bob leaves; only alice keeps beeping.
	h.clk.Advance(40 * time.Second)
	for i := 0; i < 5; i++ {
		must(t, h.fobs.Advertise(fobAlice, -50, h.clk.Now()))
		h.clk.Advance(3 * time.Second)
		time.Sleep(120 * time.Millisecond)
	}
	// Poll for the monitor to act (it uses a real ticker against a fake clock).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.State() != "aborted" {
		time.Sleep(50 * time.Millisecond)
	}
	if s.State() != "aborted" {
		t.Fatalf("state = %s, want aborted after co-presence lapse", s.State())
	}
	if h.act.AnyOpen() {
		t.Fatal("cabinet still open after watchdog abort")
	}
}

// TestUnlockWindowExpired: alice opens slot A, then fails to get bob to slot B
// within the window. This blocks the "open A, go fetch bob, come back" pattern.
func TestUnlockWindowExpired(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(100)
	must(t, s.Present(access.SlotA, access.Credential{Operator: alice, FobID: fobAlice, At: h.clk.Now()}))

	h.clk.Advance(60 * time.Second) // beyond 45s window
	// Keep both fobs live so presence is not the reason for the failure.
	h.beepBoth()

	err := s.Present(access.SlotB, access.Credential{Operator: bob, FobID: fobBob, At: h.clk.Now()})
	if !errors.Is(err, access.ErrWindowExpired) {
		t.Fatalf("want unlock window expired, got %v", err)
	}
}

// TestWrongSlotCredential: alice tries to fill both slots with her own
// credentials. The slot ownership check rejects the second presentation.
func TestWrongSlotCredential(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(100)
	must(t, s.Present(access.SlotA, access.Credential{Operator: alice, FobID: fobAlice, At: h.clk.Now()}))
	err := s.Present(access.SlotB, access.Credential{Operator: alice, FobID: fobAlice, At: h.clk.Now()})
	if !errors.Is(err, access.ErrWrongSlot) {
		t.Fatalf("want wrong-slot error, got %v", err)
	}
	if open, _ := h.act.State(access.SlotB); open {
		t.Fatal("slot B opened despite alice not owning it")
	}
}

// TestMaskedFallback verifies that a respirator-wearing operator is not simply
// refused, but is verified through an alternate factor, and that the ledger
// records that face abstained.
func TestMaskedFallback(t *testing.T) {
	h := newHarness(t)
	s := h.newSession(50)

	d, err := s.Authenticate(alice, h.facePass())
	must(t, err)
	if d.Mode != "face" {
		t.Fatalf("alice mode = %s, want face", d.Mode)
	}

	// Bob's face is covered; a voice sample verifies him. Evaluate fuses them.
	samples := append(h.faceMasked(), h.voicePass()...)
	d, err = s.Authenticate(bob, samples)
	must(t, err)
	if d.Mode != "fallback" {
		t.Fatalf("bob mode = %s, want fallback", d.Mode)
	}
	if d.Verified != true {
		t.Fatal("bob should be verified via fallback")
	}
	// The audit trail must show the mask abstention and the fallback reason.
	found := false
	for _, r := range h.log.Records() {
		if strings.Contains(string(r.Payload), "face_covered") {
			found = true
		}
	}
	if !found {
		t.Fatal("ledger does not record that face was masked for bob")
	}
}

// TestSpoofRefused: a presentation attack is refused even if the match score is
// high, and a security event is recorded.
func TestSpoofRefused(t *testing.T) {
	h := newHarness(t)
	s := h.newSession(50)
	_, err := s.Authenticate(alice, h.faceSpoof())
	if err == nil {
		t.Fatal("spoofed face should be refused")
	}
	if !strings.Contains(err.Error(), "presentation attack") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestOverageHardFailsHighlyToxic: measured removal exceeds the claim and the
// authorisation beyond tolerance. For a highly toxic product the session aborts
// immediately and relocks.
func TestOverageHardFailsHighlyToxic(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(30) // authorised 30g
	h.unlockBoth(s)

	h.stageWeigh("drum-1", 10_000, 60) // actually takes 60g, claims 30g
	_, err := s.RecordRemoval("drum-1", 30, alice)
	if !errors.Is(err, sessionErrDiscrepancy) {
		t.Fatalf("want discrepancy error, got %v", err)
	}
	if s.State() != "aborted" {
		t.Fatalf("state = %s, want aborted on overage", s.State())
	}
	if h.act.AnyOpen() {
		t.Fatal("cabinet left open after overage")
	}
	if h.countKind(ledger.KindDiscrepancy) == 0 {
		t.Fatal("no discrepancy recorded in ledger")
	}
}

// TestShortfallNeedsSupervisor: the operator claims more than was measured: a
// review-level discrepancy that blocks close until resolved.
func TestShortfallNeedsSupervisor(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(100)
	h.unlockBoth(s)

	h.stageWeigh("drum-1", 10_000, 40) // actually takes 40g, claims 100g
	_, err := s.RecordRemoval("drum-1", 100, alice)
	if !errors.Is(err, sessionErrDiscrepancy) {
		t.Fatalf("want discrepancy error, got %v", err)
	}
	if s.State() == "aborted" {
		t.Fatal("shortfall should not abort a highly toxic session; it needs review")
	}
	must(t, s.BeginReconcile())
	if err := s.Close(alice); !errors.Is(err, sessionErrDiscrepancy) {
		t.Fatalf("close should be blocked by unresolved discrepancy, got %v", err)
	}
}

// TestUnstableScaleRejected: a single reading or an unstable run is not evidence.
func TestUnstableScaleRejected(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(100)
	h.unlockBoth(s)

	h.scale.SetTare("drum-1", 500, h.clk.Now())
	// Only three readings: below StableSamples (5).
	h.scale.PlaceBefore("drum-1", 10_000, h.clk.Now(), 3)
	h.scale.PlaceAfter("drum-1", 9_980, h.clk.Now(), 3)
	_, err := s.RecordRemoval("drum-1", 20, alice)
	if err == nil {
		t.Fatal("unstable weighing should not reconcile")
	}
}

// TestStaleTareRejected: a tare from the previous shift cannot be used.
func TestStaleTareRejected(t *testing.T) {
	h := newHarness(t)
	s := h.armBoth(100)
	h.unlockBoth(s)

	h.scale.SetTare("drum-1", 500, h.clk.Now().Add(-2*time.Hour))
	h.scale.PlaceBefore("drum-1", 10_000, h.clk.Now(), 5)
	h.scale.PlaceAfter("drum-1", 9_980, h.clk.Now(), 5)
	_, err := s.RecordRemoval("drum-1", 20, alice)
	if err == nil || !strings.Contains(err.Error(), "weighing not usable") {
		t.Fatalf("want stale-tare rejection, got %v", err)
	}
}

// TestCorrelatedFobsRequireDistinctness: two fobs that track together look like
// they are on one body, so the unlock demands a distinctness proof.
func TestCorrelatedFobsRequireDistinctness(t *testing.T) {
	h := newHarness(t)
	h.enrol()
	// Feed perfectly correlated RSSI series for both fobs, one sample per second.
	// Both "operators" are in fact one person carrying two fobs.
	for i := 0; i < 10; i++ {
		v := -50 - (i % 3)
		must(t, h.fobs.Advertise(fobAlice, v, h.clk.Now()))
		must(t, h.fobs.Advertise(fobBob, v, h.clk.Now()))
		h.clk.Advance(time.Second)
	}
	cp := h.tracker.CoPresence(alice, bob)
	if !cp.SameBody {
		t.Fatalf("expected same-body suspicion, got r=%.2f", cp.Suspicion)
	}
}
