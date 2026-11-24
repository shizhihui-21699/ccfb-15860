// Package access governs the cabinet's two physical locks.
//
// The cabinet has two locks in series on different keyways (A and B). Opening
// requires both. Each lock is controlled by a different operator's credential,
// so no single credential can open the cabinet. The lock sequence is:
//
//	arm (both present) -> operator A presents to lock A -> operator B presents to
//	lock B within UnlockWindow -> door opens.
//
// Two additional rules close the "collusion then abandon" gap that a one-time
// dual unlock cannot:
//
//   - each slot's credential must belong to the operator assigned to that slot
//     for this session (a shared badge cannot fill both slots);
//   - presence is re-checked at every subsequent state transition (each item
//     removal, each relock), so the moment one operator leaves, the session
//     can no longer progress and the cabinet relocks.
package access

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/model"
)

// Slot identifies which of the two locks an action targets.
type Slot string

const (
	SlotA Slot = "A"
	SlotB Slot = "B"
)

// Other returns the opposite slot.
func (s Slot) Other() Slot {
	if s == SlotA {
		return SlotB
	}
	return SlotA
}

// Actuator is the physical lock. Real implementations drive a solenoid and read
// a bolt sensor; the returned error means the lock did not confirm.
type Actuator interface {
	// Open energises the lock for slot s. It returns once the bolt sensor
	// confirms open, or an error.
	Open(s Slot) error
	// Close de-energises and confirms the bolt is seated.
	Close(s Slot) error
	// State reports the last known physical state.
	State(s Slot) (open bool, err error)
}

// PresenceChecker is the subset of presence.Tracker the access layer needs. It
// is an interface so the state machine can be tested with a scripted checker.
type PresenceChecker interface {
	// BothLive reports whether both named operators are live at the cabinet.
	BothLive(a, b model.OperatorID) (ok bool, detail string)
}

// Credential is what an operator presents to a lock.
type Credential struct {
	Operator model.OperatorID
	FobID    string
	// DistinctnessProof is a short-lived challenge response (e.g. a one-time
	// code typed by each operator on their own console, or a pairwise BLE
	// handshake) produced after the presence layer flagged possible same-body
	// carriage. Empty when not required.
	DistinctnessProof string
	At                time.Time
}

// Config is the lock policy.
type Config struct {
	// UnlockWindow is the maximum time between the first and second slot opening.
	// Short enough that one operator cannot open A, walk to a colleague, and
	// return. It is the core mitigation for the sequential-unlock race.
	UnlockWindow time.Duration
	// RelockWindow is the maximum time a door may stay open between removals
	// without progress before it auto-relocks.
	RelockWindow time.Duration
	// RequireDistinctness makes the distinctness proof mandatory whenever the
	// presence layer reports correlation. Always true in production.
	RequireDistinctness bool
}

func DefaultConfig() Config {
	return Config{
		UnlockWindow:        45 * time.Second,
		RelockWindow:        10 * time.Minute,
		RequireDistinctness: true,
	}
}

// ErrNotArmed is returned when the cabinet is not in the armed state.
var ErrNotArmed = errors.New("access: cabinet not armed")

// ErrWrongSlot is returned when a credential names an operator not assigned to
// the slot it was presented to.
var ErrWrongSlot = errors.New("access: credential does not belong to this slot")

// ErrWindowExpired is returned when the second unlock arrives too late.
var ErrWindowExpired = errors.New("access: unlock window expired")

// ErrPresenceLost is returned when a presence re-check fails mid-operation.
var ErrPresenceLost = errors.New("access: required presence lost")

// ErrNotDistinct is returned when the distinctness proof is missing or wrong.
var ErrNotDistinct = errors.New("access: distinctness proof required or invalid")

// DualLock is the two-slot lock controller. It holds session-scoped state and
// enforces the ordering and timing rules above.
type DualLock struct {
	mu   sync.Mutex
	cfg  Config
	clk  clock.Clock
	act  Actuator
	pc   PresenceChecker
	dist DistinctnessVerifier

	// session-scoped
	sessionID string
	assign    map[Slot]model.OperatorID
	armedAt   time.Time
	armed     bool
	firstAt   time.Time // time the first slot was opened
	opened    map[Slot]bool
	openAt    map[Slot]time.Time
	lastEvent time.Time
	// needDistinct is set for the current session only when the presence layer
	// flagged correlation. It is deliberately session-scoped: a single
	// correlation event must not permanently raise the bar for every later
	// session (that would be a fail-open on usability and a fail-ugly on audit).
	needDistinct bool
}

// DistinctnessVerifier validates a distinctness proof bound to a session and an
// operator.
type DistinctnessVerifier interface {
	Verify(sessionID string, op model.OperatorID, proof string) bool
}

// New builds a controller.
func New(cfg Config, clk clock.Clock, act Actuator, pc PresenceChecker, dist DistinctnessVerifier) *DualLock {
	return &DualLock{
		cfg: cfg, clk: clk, act: act, pc: pc, dist: dist,
		assign: make(map[Slot]model.OperatorID),
		opened: make(map[Slot]bool),
		openAt: make(map[Slot]time.Time),
	}
}

// Arm binds a session to two specific operators, one per slot. It clears any
// prior lock state, so a session cannot inherit an open door.
func (d *DualLock) Arm(sessionID string, a, b model.OperatorID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a == "" || b == "" || a == b {
		return fmt.Errorf("access: arm needs two distinct operators, got %q and %q", a, b)
	}
	// Fail closed: make sure the door is actually shut before arming.
	for _, s := range []Slot{SlotA, SlotB} {
		if open, err := d.act.State(s); err == nil && open {
			if err := d.act.Close(s); err != nil {
				return fmt.Errorf("access: cannot close %s before arming: %w", s, err)
			}
		}
	}
	d.sessionID = sessionID
	d.assign = map[Slot]model.OperatorID{SlotA: a, SlotB: b}
	d.armedAt = d.clk.Now()
	d.armed = true
	d.firstAt = time.Time{}
	d.opened = map[Slot]bool{}
	d.openAt = map[Slot]time.Time{}
	d.lastEvent = d.armedAt
	d.needDistinct = d.cfg.RequireDistinctness
	return nil
}

// Disarm tears down the session and relocks everything.
func (d *DualLock) Disarm() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var firstErr error
	for _, s := range []Slot{SlotA, SlotB} {
		if err := d.act.Close(s); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	d.armed = false
	return firstErr
}

// Armed reports whether the controller is armed and for which session.
func (d *DualLock) Armed() (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessionID, d.armed
}

// Present handles a credential presented to slot s. It enforces slot ownership,
// presence, distinctness and windowing, then opens that slot.
//
// The order of checks matters: presence and distinctness are validated *before*
// the actuator is driven, so a failing check never exposes the lock.
func (d *DualLock) Present(s Slot, c Credential) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.armed {
		return ErrNotArmed
	}
	if c.Operator != d.assign[s] {
		return fmt.Errorf("%w: %s presented to slot %s", ErrWrongSlot, c.Operator, s)
	}
	if d.opened[s] {
		return nil // idempotent: already open for this session
	}
	// Presence must hold at the moment of each unlock, not just at arm time.
	a, b := d.assign[SlotA], d.assign[SlotB]
	if ok, detail := d.pc.BothLive(a, b); !ok {
		return fmt.Errorf("%w: %s", ErrPresenceLost, detail)
	}
	// Distinctness: when required, the proof must be present and valid. Even
	// when not required, a supplied proof is still checked so a bogus one
	// cannot be recorded as if it had been honoured.
	if c.DistinctnessProof != "" {
		if d.dist == nil || !d.dist.Verify(d.sessionID, c.Operator, c.DistinctnessProof) {
			return ErrNotDistinct
		}
	} else if d.needDistinct {
		return fmt.Errorf("%w: slot %s", ErrNotDistinct, s)
	}
	now := d.clk.Now()
	if len(d.opened) > 0 {
		// Second (or later) slot: enforce the window from the first open.
		if now.Sub(d.firstAt) > d.cfg.UnlockWindow {
			return fmt.Errorf("%w: %.0fs elapsed, limit %s", ErrWindowExpired, now.Sub(d.firstAt).Seconds(), d.cfg.UnlockWindow)
		}
	}
	if err := d.act.Open(s); err != nil {
		return fmt.Errorf("access: actuator open %s: %w", s, err)
	}
	d.opened[s] = true
	d.openAt[s] = now
	if d.firstAt.IsZero() {
		d.firstAt = now
	}
	d.lastEvent = now
	return nil
}

// RequireDistinctnessFor marks that the current session needs a distinctness
// proof because the presence layer flagged correlation. When set, both
// credentials must carry a valid proof.
func (d *DualLock) RequireDistinctnessFor(sessionID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessionID == sessionID {
		d.needDistinct = true
	}
}

// Touch records progress (e.g. an item was scanned) and re-verifies presence.
// The session calls this before each removal; a failure means the caller must
// abort and relock.
func (d *DualLock) Touch() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.armed {
		return ErrNotArmed
	}
	a, b := d.assign[SlotA], d.assign[SlotB]
	if ok, detail := d.pc.BothLive(a, b); !ok {
		return fmt.Errorf("%w: %s", ErrPresenceLost, detail)
	}
	d.lastEvent = d.clk.Now()
	return nil
}

// DoorsOpen reports whether both locks are open (the normal removal state).
func (d *DualLock) DoorsOpen() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.opened[SlotA] && d.opened[SlotB]
}

// OpenedAt returns when the given slot was last opened this session.
func (d *DualLock) OpenedAt(s Slot) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.openAt[s]
}

// IdleSinceLastEvent returns how long since the last recorded progress.
func (d *DualLock) IdleSinceLastEvent() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lastEvent.IsZero() {
		return 0
	}
	return d.clk.Now().Sub(d.lastEvent)
}

// Watchdog should be invoked periodically. It force-relocks a session whose
// door has been open too long without progress, and this is the safety net for
// a session abandoned mid-way. It returns whether it relocked.
func (d *DualLock) Watchdog() (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.armed || len(d.opened) == 0 {
		return false, nil
	}
	if d.clk.Now().Sub(d.lastEvent) <= d.cfg.RelockWindow {
		return false, nil
	}
	var firstErr error
	for _, s := range []Slot{SlotA, SlotB} {
		if err := d.act.Close(s); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	d.opened = map[Slot]bool{}
	d.armed = false
	return true, firstErr
}
