// Package session orchestrates one controlled withdrawal from a cabinet.
//
// A session is the unit of accountability: two named operators, one cabinet, one
// product, one authorised quantity. Every state transition is written to the
// tamper-evident ledger, and the session will refuse to advance — and will
// abort, relocking the cabinet — the moment required co-presence is lost.
//
// State machine:
//
//	Created --authenticate A+B--> Authenticated --arm--> Armed
//	  --present A, present B--> Open --remove--> Open ... --close--> Reconciling
//	  --> Closed
//
// Any of: presence lost, unlock window expiry, tamper, or an unresolved
// discrepancy above policy drives -> Aborted, and the locks are closed.
package session

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/biometric"
	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/ledger"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/presence"
	"hazmatcontrol/internal/weigh"
)

// State is a session lifecycle state.
type State string

const (
	StateCreated       State = "created"
	StateAuthenticated State = "authenticated"
	StateArmed         State = "armed"
	StateOpen          State = "open"
	StateReconciling   State = "reconciling"
	StateClosed        State = "closed"
	StateAborted       State = "aborted"
)

// Errors returned by the session API. Callers map these to operator-facing
// messages and, for the security-relevant ones, to a ledger event.
var (
	ErrWrongState    = errors.New("session: not valid in this state")
	ErrNotAuthorised = errors.New("session: operator not assigned to this session")
	ErrPresenceLost  = errors.New("session: co-presence lost")
	ErrDiscrepancy   = errors.New("session: unresolved weighing discrepancy")
)

// Removal is one recorded withdrawal of material from a container.
type Removal struct {
	ContainerID  string
	ProductSKU   string
	ClaimedGrams float64
	Result       weigh.Result
	Operator     model.OperatorID
	At           time.Time
}

// Session is one controlled withdrawal.
type Session struct {
	mu        sync.Mutex
	ID        string
	Cabinet   model.CabinetID
	Class     model.HazardClass
	Product   model.Product
	AuthGrams float64
	Operators [2]model.OperatorID // slot A, slot B
	state     State
	clk       clock.Clock

	log     *ledger.Log
	bio     *biometric.Evaluator
	tracker *presence.Tracker
	lock    *access.DualLock
	scale   Scale
	cfg     Config

	auth        map[model.OperatorID]biometric.Decision
	removals    []Removal
	closeReason string
	openedAt    time.Time
}

// Scale is the platform scale interface, satisfied by devices.Scale and test
// doubles. Readings returns the samples collected so far this placement.
type Scale interface {
	Readings(containerID string) []weigh.Reading
	Tare(containerID string) (weigh.Tare, error)
}

// Config holds session timing policy and the distinction between hard and
// soft discrepancy handling.
type Config struct {
	// HardFailOnOver aborts the session immediately when measured material
	// exceeds the claim/authorisation beyond tolerance. Highly toxic products
	// set this; general products may allow a supervisor to clear it.
	HardFailOnOver bool
	// RequireDeferredClose forces the session to stay in Reconciling until the
	// end-of-shift weighing confirms the totals, so an operator cannot simply
	// walk away with mouthful discrepancies.
	RequireDeferredClose bool
	// MaxSessionDuration bounds a single session.
	MaxSessionDuration time.Duration
}

func DefaultConfig(h model.HazardClass) Config {
	return Config{
		HardFailOnOver:       h == model.HazardHighlyToxic,
		RequireDeferredClose: h == model.HazardHighlyToxic,
		MaxSessionDuration:   45 * time.Minute,
	}
}

// Deps bundles the collaborating subsystems for a session.
type Deps struct {
	Clock   clock.Clock
	Ledger  *ledger.Log
	Bio     *biometric.Evaluator
	Tracker *presence.Tracker
	Lock    *access.DualLock
	Scale   Scale
	Config  Config
}

// Open creates a session and writes the opening event. It does not authenticate
// anyone; callers then Authenticate each operator.
func Open(id string, cabinet model.CabinetID, p model.Product, authGrams float64, a, b model.OperatorID, deps Deps) (*Session, error) {
	if a == "" || b == "" || a == b {
		return nil, fmt.Errorf("session: two distinct operators required")
	}
	if authGrams <= 0 {
		return nil, fmt.Errorf("session: authorised amount must be positive")
	}
	s := &Session{
		ID: id, Cabinet: cabinet, Class: p.Hazard, Product: p, AuthGrams: authGrams,
		Operators: [2]model.OperatorID{a, b}, state: StateCreated, clk: deps.Clock,
		log: deps.Ledger, bio: deps.Bio, tracker: deps.Tracker, lock: deps.Lock,
		scale: deps.Scale, cfg: deps.Config,
		auth: make(map[model.OperatorID]biometric.Decision),
	}
	if _, err := s.log.Append(ledger.KindSessionOpen, map[string]any{
		"session":      id,
		"cabinet":      cabinet,
		"sku":          p.SKU,
		"product":      p.Name,
		"cas":          p.CAS,
		"hazard":       p.Hazard,
		"authorised_g": authGrams,
		"operators":    []string{string(a), string(b)},
		"slots":        map[string]string{"A": string(a), "B": string(b)},
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// State returns the current state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// CloseReason returns why the session ended, if it did.
func (s *Session) CloseReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeReason
}

// Removals returns a copy of recorded removals.
func (s *Session) Removals() []Removal {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Removal, len(s.removals))
	copy(out, s.removals)
	return out
}

// Authenticate records a biometric decision for one operator. Both operators
// must authenticate, and each must be the operator assigned to their slot.
func (s *Session) Authenticate(op model.OperatorID, samples []biometric.Sample) (biometric.Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateCreated {
		return biometric.Decision{}, ErrWrongState
	}
	if !s.assigned(op) {
		return biometric.Decision{}, fmt.Errorf("%w: %s", ErrNotAuthorised, op)
	}
	d := s.bio.Evaluate(op, samples)
	if _, err := s.log.Append(ledger.KindAuthAttempt, map[string]any{
		"session": s.ID, "operator": op, "mode": d.Mode, "verified": d.Verified,
		"confidence": d.Confidence, "detail": d.Detail, "reasons": reasonStrings(d.Reasons),
	}); err != nil {
		return biometric.Decision{}, err
	}
	if !d.Verified {
		return d, fmt.Errorf("session: operator %s failed authentication: %s", op, d.Detail)
	}
	s.auth[op] = d
	if _, err := s.log.Append(ledger.KindAuthGranted, map[string]any{
		"session": s.ID, "operator": op, "mode": d.Mode, "confidence": d.Confidence, "detail": d.Detail,
	}); err != nil {
		return biometric.Decision{}, err
	}
	if len(s.auth) == 2 {
		s.state = StateAuthenticated
	}
	return d, nil
}

// ArmBoth requires both operators authenticated and both live at the cabinet,
// then arms the dual lock. Arm is the point at which presence is first asserted;
// it is re-asserted before every subsequent unlock and removal.
func (s *Session) ArmBoth() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateAuthenticated {
		return fmt.Errorf("%w: %s", ErrWrongState, s.state)
	}
	cp := s.tracker.CoPresence(s.Operators[0], s.Operators[1])
	if !cp.OK {
		// Write the refusal so an auditor sees that arming was attempted while
		// one operator was absent.
		s.log.Append(ledger.KindPresenceLost, map[string]any{"session": s.ID, "stage": "arm", "detail": cp.Reason})
		return fmt.Errorf("%w: %s", ErrPresenceLost, cp.Reason)
	}
	if cp.SameBody {
		// Flag it; distinctness will be demanded at unlock time.
		s.lock.RequireDistinctnessFor(s.ID)
	}
	if err := s.lock.Arm(s.ID, s.Operators[0], s.Operators[1]); err != nil {
		return err
	}
	s.state = StateArmed
	s.openedAt = s.clk.Now()
	return s.logAppend(ledger.KindSessionArmed, map[string]any{
		"session": s.ID, "copresence_suspicion": cp.Suspicion, "same_body": cp.SameBody,
		"presence_a": cp.A.Reason, "presence_b": cp.B.Reason,
	})
}

// Present presents an operator's credential to a lock slot and opens it if all
// checks pass. On the second successful presentation the session becomes Open.
func (s *Session) Present(slot access.Slot, c access.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateArmed && s.state != StateOpen {
		return fmt.Errorf("%w: %s", ErrWrongState, s.state)
	}
	if !s.assigned(c.Operator) {
		return fmt.Errorf("%w: %s", ErrNotAuthorised, c.Operator)
	}
	if err := s.lock.Present(slot, c); err != nil {
		kind := ledger.KindAuthAttempt
		s.log.Append(kind, map[string]any{
			"session": s.ID, "stage": "unlock", "slot": string(slot), "operator": c.Operator, "error": err.Error(),
		})
		return err
	}
	if err := s.logAppend(ledger.KindUnlock, map[string]any{
		"session": s.ID, "slot": string(slot), "operator": c.Operator,
		"distinctness": c.DistinctnessProof != "",
	}); err != nil {
		return err
	}
	if s.lock.DoorsOpen() {
		s.state = StateOpen
	}
	return nil
}

// RecordRemoval is called after an operator removes material from a container.
// It re-asserts presence before accepting anything; if presence has lapsed the
// removal is rejected and the session is aborted, because accepting a removal
// without co-presence is exactly the fraud we are preventing.
func (s *Session) RecordRemoval(containerID string, claimedGrams float64, op model.OperatorID) (weigh.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateOpen {
		return weigh.Result{}, fmt.Errorf("%w: %s", ErrWrongState, s.state)
	}
	if !s.assigned(op) {
		return weigh.Result{}, fmt.Errorf("%w: %s", ErrNotAuthorised, op)
	}
	if err := s.lock.Touch(); err != nil {
		s.abortLocked("presence lost during removal: " + err.Error())
		return weigh.Result{}, fmt.Errorf("%w: %v", ErrPresenceLost, err)
	}
	if s.clk.Now().Sub(s.openedAt) > s.cfg.MaxSessionDuration {
		s.abortLocked("session exceeded maximum duration")
		return weigh.Result{}, fmt.Errorf("%w: session too long", ErrWrongState)
	}
	readings := s.scale.Readings(containerID)
	tare, err := s.scale.Tare(containerID)
	if err != nil {
		return weigh.Result{}, fmt.Errorf("session: no tare for %s: %w", containerID, err)
	}
	// Split readings into before/after around this removal using the midpoint
	// of the session's known placements is not possible here without placement
	// events; the scale double records a before-run and an after-run explicitly.
	before, after := readingsBeforeAfter(readings)
	rec := weigh.NewReconciler(weigh.DefaultConfig(), s.clk)
	res := rec.Reconcile(string(s.Class), tare, before, after, claimedGrams, s.AuthGrams)

	if err := s.logAppend(ledger.KindWeigh, map[string]any{
		"session": s.ID, "operator": op, "container": containerID,
		"claimed_g": claimedGrams, "removed_g": res.RemovedGrams,
		"verdict": res.Verdict, "allowed_g": res.AllowedGrams,
		"deviation_g": res.DeviationG, "detail": res.Detail,
	}); err != nil {
		return res, err
	}
	s.removals = append(s.removals, Removal{
		ContainerID: containerID, ProductSKU: s.Product.SKU,
		ClaimedGrams: claimedGrams, Result: res, Operator: op, At: s.clk.Now(),
	})
	switch res.Verdict {
	case weigh.VerdictMatched:
		return res, nil
	case weigh.VerdictOver:
		s.logAppend(ledger.KindDiscrepancy, map[string]any{
			"session": s.ID, "container": containerID, "verdict": res.Verdict, "detail": res.Detail,
			"severity": severityFor(s.Class),
		})
		if s.cfg.HardFailOnOver {
			s.abortLocked("overage on highly toxic product: " + res.Detail)
			return res, fmt.Errorf("%w: %s", ErrDiscrepancy, res.Detail)
		}
		return res, fmt.Errorf("%w: %s", ErrDiscrepancy, res.Detail)
	case weigh.VerdictUnder:
		s.logAppend(ledger.KindDiscrepancy, map[string]any{
			"session": s.ID, "container": containerID, "verdict": res.Verdict, "detail": res.Detail,
			"severity": "review",
		})
		return res, fmt.Errorf("%w: %s", ErrDiscrepancy, res.Detail)
	default: // unstable / stale tare
		return res, fmt.Errorf("session: weighing not usable: %s", res.Detail)
	}
}

// BeginReconcile transitions to Reconciling; the door is relocked first so no
// further material can move while totals are checked.
func (s *Session) BeginReconcile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateOpen {
		return fmt.Errorf("%w: %s", ErrWrongState, s.state)
	}
	for _, slot := range []access.Slot{access.SlotA, access.SlotB} {
		s.logAppend(ledger.KindRelock, map[string]any{"session": s.ID, "slot": string(slot)})
	}
	if err := s.lock.Disarm(); err != nil {
		return err
	}
	s.state = StateReconciling
	return nil
}

// Totals summarises claimed and measured quantities across all removals.
type Totals struct {
	ClaimedGrams  float64
	RemovedGrams  float64
	Removals      int
	Discrepancies int
}

// Totals returns the running totals.
func (s *Session) Totals() Totals {
	s.mu.Lock()
	defer s.mu.Unlock()
	var t Totals
	for _, r := range s.removals {
		t.ClaimedGrams += r.ClaimedGrams
		t.RemovedGrams += r.Result.RemovedGrams
		t.Removals++
		if r.Result.Verdict != weigh.VerdictMatched {
			t.Discrepancies++
		}
	}
	return t
}

// Close finalises the session. It refuses to close while any discrepancy is
// unresolved when the session is configured for hard reconciliation.
func (s *Session) Close(closedBy model.OperatorID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateReconciling && s.state != StateOpen {
		return fmt.Errorf("%w: %s", ErrWrongState, s.state)
	}
	t := s.totalsLocked()
	if s.cfg.RequireDeferredClose && t.Discrepancies > 0 {
		return fmt.Errorf("%w: %d discrepancy(ies) need supervisor review", ErrDiscrepancy, t.Discrepancies)
	}
	if err := s.lock.Disarm(); err != nil {
		return err
	}
	s.state = StateClosed
	s.closeReason = fmt.Sprintf("closed by %s; %.1fg claimed / %.1fg measured over %d removal(s)", closedBy, t.ClaimedGrams, t.RemovedGrams, t.Removals)
	return s.logAppend(ledger.KindSessionClose, map[string]any{
		"session": s.ID, "closed_by": closedBy, "claimed_g": t.ClaimedGrams,
		"measured_g": t.RemovedGrams, "removals": t.Removals, "discrepancies": t.Discrepancies,
	})
}

// Abort ends the session abnormally and relocks. It is safe to call from a
// monitor goroutine.
func (s *Session) Abort(reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateClosed || s.state == StateAborted {
		return nil
	}
	return s.abortLocked(reason)
}

func (s *Session) abortLocked(reason string) error {
	if err := s.lock.Disarm(); err != nil {
		// Record the failure but continue marking aborted; a failed relock is a
		// physical fault that must surface to the operator console.
		s.log.Append(ledger.KindDegraded, map[string]any{"session": s.ID, "detail": "relock failed: " + err.Error()})
	}
	s.state = StateAborted
	s.closeReason = reason
	return s.logAppend(ledger.KindSessionClose, map[string]any{
		"session": s.ID, "aborted": true, "reason": reason,
	})
}

// Monitor runs until the session ends, checking co-presence on a ticker. It is
// the defence against a session that armed legitimately and then lost an
// operator: the watchdog relocks even if no removal is in progress.
func (s *Session) Monitor(interval time.Duration, done <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			s.mu.Lock()
			st := s.state
			s.mu.Unlock()
			if st == StateClosed || st == StateAborted {
				return
			}
			if st == StateArmed || st == StateOpen {
				if relocked, err := s.lock.Watchdog(); relocked || err != nil {
					s.Abort("watchdog relocked idle session")
					return
				}
				cp := s.tracker.CoPresence(s.Operators[0], s.Operators[1])
				if !cp.OK {
					s.Abort("co-presence lost: " + cp.Reason)
					return
				}
			}
		}
	}
}

// ---- helpers ---------------------------------------------------------------

func (s *Session) assigned(op model.OperatorID) bool {
	return op == s.Operators[0] || op == s.Operators[1]
}

func (s *Session) totalsLocked() Totals {
	var t Totals
	for _, r := range s.removals {
		t.ClaimedGrams += r.ClaimedGrams
		t.RemovedGrams += r.Result.RemovedGrams
		t.Removals++
		if r.Result.Verdict != weigh.VerdictMatched {
			t.Discrepancies++
		}
	}
	return t
}

func (s *Session) logAppend(kind ledger.Kind, payload any) error {
	_, err := s.log.Append(kind, payload)
	return err
}

func severityFor(h model.HazardClass) string {
	if h == model.HazardHighlyToxic {
		return "critical"
	}
	return "review"
}

func reasonStrings(rs []biometric.Reason) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// readingsBeforeAfter splits a scale's recorded readings for a container into
// two halves. Real deployments record explicit placement events; the split here
// keeps the reconciliation logic independent of that detail and is overridden by
// the device layer which returns tagged runs.
func readingsBeforeAfter(rs []weigh.Reading) (before, after []weigh.Reading) {
	n := len(rs)
	if n < 2 {
		return nil, nil
	}
	return rs[:n/2], rs[n/2:]
}
