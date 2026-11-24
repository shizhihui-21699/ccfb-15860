package session_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/biometric"
	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/devices"
	"hazmatcontrol/internal/ledger"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/presence"
	"hazmatcontrol/internal/session"
)

// Aliases for the session package's sentinel errors, so the tests read cleanly.
var (
	sessionErrPresence    = session.ErrPresenceLost
	sessionErrDiscrepancy = session.ErrDiscrepancy
)

// harness wires a full controller stack with a controllable clock so timing
// policy (lease expiry, unlock window) can be exercised deterministically.
type harness struct {
	t       *testing.T
	clk     *clock.Fake
	log     *ledger.Log
	store   *ledger.MemStore
	tracker *presence.Tracker
	act     *devices.MemActuator
	lock    *access.DualLock
	scale   *devices.MemScale
	bio     *biometric.Evaluator
	fobs    *devices.FobSource
	dist    *distinctness
	keys    ledger.Keyring
	priv    ed25519.PrivateKey
}

type distinctness struct {
	valid map[string]bool
}

func (d *distinctness) Verify(sessionID string, op model.OperatorID, proof string) bool {
	return d.valid[string(op)+"|"+proof]
}

func (d *distinctness) issue(op model.OperatorID, proof string) string {
	d.valid[string(op)+"|"+proof] = true
	return proof
}

const (
	alice = model.OperatorID("alice")
	bob   = model.OperatorID("bob")
	carol = model.OperatorID("carol")

	fobAlice = "fob-alice"
	fobBob   = "fob-bob"
	fobCarol = "fob-carol"
)

func newHarness(t *testing.T) *harness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := ledger.Keyring{"dev-1": pub}
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	log, err := ledger.Open("cab-1", "dev-1", priv, keys, ledger.NewMemStore(), clk)
	if err != nil {
		t.Fatal(err)
	}
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	act := devices.NewMemActuator()
	dist := &distinctness{valid: map[string]bool{}}
	lock := access.New(access.Config{
		UnlockWindow: 45 * time.Second, RelockWindow: 10 * time.Minute, RequireDistinctness: false,
	}, clk, act, &presenceChecker{tr: tr}, dist)
	return &harness{
		t: t, clk: clk, log: log, tracker: tr, act: act, lock: lock,
		scale: devices.NewMemScale(), bio: biometric.NewEvaluator(biometric.DefaultConfig(), clk),
		fobs: devices.NewFobSource(tr), dist: dist, keys: keys, priv: priv,
	}
}

type presenceChecker struct{ tr *presence.Tracker }

func (p *presenceChecker) BothLive(a, b model.OperatorID) (bool, string) {
	cp := p.tr.CoPresence(a, b)
	return cp.OK, cp.Reason
}

// enrol binds three fobs: alice and bob are the session operators, carol is the
// colleague whose badge gets borrowed in the badge-sharing scenario.
func (h *harness) enrol() {
	h.t.Helper()
	must(h.t, h.tracker.BindFob(alice, fobAlice, "tok-a"))
	must(h.t, h.tracker.BindFob(bob, fobBob, "tok-b"))
	must(h.t, h.tracker.BindFob(carol, fobCarol, "tok-c"))
}

func (h *harness) beepBoth() {
	h.t.Helper()
	must(h.t, h.fobs.Advertise(fobAlice, -52, h.clk.Now()))
	must(h.t, h.fobs.Advertise(fobBob, -54, h.clk.Now()))
}

func (h *harness) newSession(authGrams float64) *session.Session {
	h.t.Helper()
	p := model.Product{
		SKU: "XY-001", Name: "试验用剧毒品", CAS: "0000-00-1",
		Hazard: model.HazardHighlyToxic, Unit: "g",
	}
	s, err := session.Open("sess-1", "cab-1", p, authGrams, alice, bob, session.Deps{
		Clock: h.clk, Ledger: h.log, Bio: h.bio, Tracker: h.tracker,
		Lock: h.lock, Scale: h.scale, Config: session.DefaultConfig(model.HazardHighlyToxic),
	})
	must(h.t, err)
	return s
}

// facePass is a strong live face match at the harness clock's current time.
func (h *harness) facePass() []biometric.Sample {
	return []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.9, Score: 0.93, Liveness: 0.95,
		Reason: biometric.ReasonOK, At: h.clk.Now(),
	}}
}

// faceMasked is a respirator-blocked capture at the harness clock's time.
func (h *harness) faceMasked() []biometric.Sample {
	return []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.2, Score: 0, Liveness: 0.5,
		Reason: biometric.ReasonMasked, At: h.clk.Now(),
	}}
}

// faceSpoof is a presentation attack (a photo held up to the camera).
func (h *harness) faceSpoof() []biometric.Sample {
	return []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.85, Score: 0.91, Liveness: 0.2,
		Reason: biometric.ReasonSpoofSuspected, At: h.clk.Now(),
	}}
}

func (h *harness) voicePass() []biometric.Sample {
	return []biometric.Sample{{
		Modality: biometric.ModVoice, Quality: 0.8, Score: 0.86, Liveness: 0.9,
		Reason: biometric.ReasonOK, At: h.clk.Now(),
	}}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// authenticatedBoth opens a session and authenticates both operators by face.
func (h *harness) authenticatedBoth(authGrams float64) *session.Session {
	h.t.Helper()
	s := h.newSession(authGrams)
	_, err := s.Authenticate(alice, h.facePass())
	must(h.t, err)
	_, err = s.Authenticate(bob, h.facePass())
	must(h.t, err)
	return s
}

// armBoth authenticates and arms with both fobs live.
func (h *harness) armBoth(authGrams float64) *session.Session {
	h.t.Helper()
	s := h.authenticatedBoth(authGrams)
	h.enrol()
	h.beepBoth()
	must(h.t, s.ArmBoth())
	return s
}

// unlockBoth presents alice to A and bob to B, opening the cabinet.
func (h *harness) unlockBoth(s *session.Session) {
	h.t.Helper()
	must(h.t, s.Present(access.SlotA, access.Credential{Operator: alice, FobID: fobAlice, At: h.clk.Now()}))
	must(h.t, s.Present(access.SlotB, access.Credential{Operator: bob, FobID: fobBob, At: h.clk.Now()}))
}

// stageWeigh sets up a tare and before/after runs for a removal of removedG
// grams, where grossStart is the container's full gross weight.
func (h *harness) stageWeigh(container string, grossStart, removedG float64) {
	h.t.Helper()
	h.scale.SetTare(container, 500, h.clk.Now())
	h.scale.PlaceBefore(container, grossStart, h.clk.Now(), 5)
	h.scale.PlaceAfter(container, grossStart-removedG, h.clk.Now(), 5)
}

// kindsIn reports how many ledger records have the given kind.
func (h *harness) countKind(k ledger.Kind) int {
	n := 0
	for _, r := range h.log.Records() {
		if r.Kind == k {
			n++
		}
	}
	return n
}
