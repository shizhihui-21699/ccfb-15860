// Package sim wires the whole controller stack (presence, biometrics, dual lock,
// weighing, session, ledger, sync) into a runnable scenario. It is used by the
// demo binary and by integration tests.
package sim

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/biometric"
	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/devices"
	"hazmatcontrol/internal/edge"
	"hazmatcontrol/internal/ledger"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/presence"
	"hazmatcontrol/internal/session"
)

// Stack is a fully wired controller plus its enrolled people and devices.
type Stack struct {
	Clk     *clock.Fake
	Edge    *edge.Controller
	Tracker *presence.Tracker
	Act     *devices.MemActuator
	Lock    *access.DualLock
	Scale   *devices.MemScale
	Bio     *biometric.Evaluator
	Fobs    *devices.FobSource
	Dist    *Distinctness

	Keys ledger.Keyring
	Priv ed25519.PrivateKey
}

// Distinctness is a simple in-memory proof registry: an operator can obtain a
// one-time code from their own console, and the verifier accepts it once.
type Distinctness struct {
	valid map[string]bool
}

func (d *Distinctness) Verify(sessionID string, op model.OperatorID, proof string) bool {
	key := string(op) + "|" + proof
	if d.valid[key] {
		delete(d.valid, key) // one-time
		return true
	}
	return false
}

// Issue mints a one-time distinctness proof for op.
func (d *Distinctness) Issue(op model.OperatorID) string {
	proof := fmt.Sprintf("dp-%s-%d", op, len(d.valid)+1)
	d.valid[string(op)+"|"+proof] = true
	return proof
}

// New builds a stack rooted at dir (for durable outbox/state).
func New(dir string, start time.Time) (*Stack, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	keys := ledger.Keyring{"cab-1-key": pub}
	clk := clock.NewFake(start)
	store, err := ledger.OpenFileStore(dir + "/ledger.jsonl")
	if err != nil {
		return nil, err
	}
	c, err := edge.Boot(edge.Options{
		Device: "cab-1", KeyID: "cab-1-key", Priv: priv, Keys: keys,
		Store: store, State: edge.NewStateFile(dir + "/state.json"),
		QueueDir: dir + "/outbox", Clock: clk,
	})
	if err != nil {
		return nil, err
	}
	tr := presence.NewTracker(presence.DefaultConfig(), clk)
	act := devices.NewMemActuator()
	dist := &Distinctness{valid: map[string]bool{}}
	lock := access.New(access.Config{
		UnlockWindow: 45 * time.Second, RelockWindow: 10 * time.Minute, RequireDistinctness: false,
	}, clk, act, &presenceAdapter{tr: tr}, dist)
	return &Stack{
		Clk: clk, Edge: c, Tracker: tr, Act: act, Lock: lock,
		Scale: devices.NewMemScale(), Bio: biometric.NewEvaluator(biometric.DefaultConfig(), clk),
		Fobs: devices.NewFobSource(tr), Dist: dist, Keys: keys, Priv: priv,
	}, nil
}

type presenceAdapter struct{ tr *presence.Tracker }

func (p *presenceAdapter) BothLive(a, b model.OperatorID) (bool, string) {
	cp := p.tr.CoPresence(a, b)
	return cp.OK, cp.Reason
}

// EnrolOperator binds a fob to an operator.
func (s *Stack) EnrolOperator(op model.OperatorID, fob string) error {
	return s.Tracker.BindFob(op, fob, "tok-"+string(op))
}

// Beep emits one on-body advertisement per fob.
func (s *Stack) Beep(fob string, rssi int) error {
	return s.Fobs.Advertise(fob, rssi, s.Clk.Now())
}

// NewSession opens a controlled withdrawal using the edge controller's ledger.
func (s *Stack) NewSession(id string, p model.Product, authGrams float64, a, b model.OperatorID) (*session.Session, error) {
	return session.Open(id, "cab-1", p, authGrams, a, b, session.Deps{
		Clock: s.Clk, Ledger: s.Edge.Ledger(), Bio: s.Bio, Tracker: s.Tracker,
		Lock: s.Lock, Scale: s.Scale, Config: session.DefaultConfig(p.Hazard),
	})
}
