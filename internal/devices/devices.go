// Package devices provides simulated and interface-compatible implementations of
// the cabinet's physical peripherals. The interfaces live with their consumers
// (access.Actuator, session.Scale) so real drivers can be dropped in without
// touching policy code.
package devices

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/presence"
	"hazmatcontrol/internal/weigh"
)

// ErrActuatorFault simulates a bolt that did not confirm.
var ErrActuatorFault = errors.New("devices: actuator failed to confirm")

// MemActuator is an in-memory dual lock. It records the order and timing of
// every open/close so tests can assert on physical behaviour, not just policy.
type MemActuator struct {
	mu       sync.Mutex
	open     map[access.Slot]bool
	events   []ActuatorEvent
	failNext map[access.Slot]bool
}

type ActuatorEvent struct {
	Slot access.Slot
	Open bool
	At   time.Time
}

func NewMemActuator() *MemActuator {
	return &MemActuator{open: map[access.Slot]bool{}, failNext: map[access.Slot]bool{}}
}

func (a *MemActuator) Open(s access.Slot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failNext[s] {
		a.failNext[s] = false
		return fmt.Errorf("%w: %s", ErrActuatorFault, s)
	}
	a.open[s] = true
	a.events = append(a.events, ActuatorEvent{Slot: s, Open: true, At: time.Now()})
	return nil
}

func (a *MemActuator) Close(s access.Slot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.open[s] = false
	a.events = append(a.events, ActuatorEvent{Slot: s, Open: false, At: time.Now()})
	return nil
}

func (a *MemActuator) State(s access.Slot) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.open[s], nil
}

// FailNext makes the next Open of s fail once.
func (a *MemActuator) FailNext(s access.Slot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failNext[s] = true
}

// AnyOpen reports whether either lock is currently open.
func (a *MemActuator) AnyOpen() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.open[access.SlotA] || a.open[access.SlotB]
}

// Events returns recorded actuator events.
func (a *MemActuator) Events() []ActuatorEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ActuatorEvent, len(a.events))
	copy(out, a.events)
	return out
}

// MemScale simulates a platform scale. It models container gross weight and
// records tagged "before" and "after" runs so the reconciler sees two stable
// sets rather than one blended stream.
type MemScale struct {
	mu     sync.Mutex
	tare   map[string]weigh.Tare
	before map[string][]weigh.Reading
	after  map[string][]weigh.Reading
	noise  float64 // grams of deterministic wobble
}

func NewMemScale() *MemScale {
	return &MemScale{
		tare:   map[string]weigh.Tare{},
		before: map[string][]weigh.Reading{},
		after:  map[string][]weigh.Reading{},
		noise:  0.3,
	}
}

// SetTare registers a container's empty weight as of now.
func (s *MemScale) SetTare(container string, emptyGrams float64, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tare[container] = weigh.Tare{ContainerID: container, Grams: emptyGrams, At: at, ScaleID: "scale-1"}
}

// StableRun generates n stable readings around a target gross weight.
func (s *MemScale) StableRun(container string, grossGrams float64, at time.Time, n int) []weigh.Reading {
	out := make([]weigh.Reading, n)
	for i := 0; i < n; i++ {
		// Deterministic tiny wobble; never exceeds the 2g stable spread.
		wobble := float64((i%3)-1) * s.noise
		out[i] = weigh.Reading{
			ContainerID: container, Grams: grossGrams + wobble, Stable: true,
			At: at.Add(time.Duration(i) * 200 * time.Millisecond), ScaleID: "scale-1",
		}
	}
	return out
}

// PlaceBefore records the pre-removal weighing run.
func (s *MemScale) PlaceBefore(container string, grossGrams float64, at time.Time, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.before[container] = s.StableRun(container, grossGrams, at, n)
}

// PlaceAfter records the post-removal weighing run.
func (s *MemScale) PlaceAfter(container string, grossGrams float64, at time.Time, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.after[container] = s.StableRun(container, grossGrams, at, n)
}

// Readings returns before then after, matching session.readingsBeforeAfter's
// equal-halves split.
func (s *MemScale) Readings(container string) []weigh.Reading {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.before[container]
	a := s.after[container]
	n := len(b)
	if len(a) > n {
		n = len(a)
	}
	// Interleave is wrong for the split; return before-run followed by after-run
	// of equal length so halves are clean.
	if len(b) != len(a) {
		// Pad the shorter run with its last stable sample so halves stay aligned.
		for len(b) < len(a) {
			b = append(b, b[len(b)-1])
		}
		for len(a) < len(b) {
			a = append(a, a[len(a)-1])
		}
	}
	out := make([]weigh.Reading, 0, len(b)+len(a))
	out = append(out, b...)
	out = append(out, a...)
	return out
}

func (s *MemScale) Tare(container string) (weigh.Tare, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tare[container]
	if !ok {
		return weigh.Tare{}, fmt.Errorf("no tare for %s", container)
	}
	return t, nil
}

// ScriptedChallenger is a biometric.Challenger that replays a script of samples.
// A production implementation would drive the console camera and microphone.
type ScriptedChallenger struct {
	mu     sync.Mutex
	script map[model.OperatorID]map[string][]Sample
	used   map[string]int
}

// Sample is a device-level capture result. It mirrors biometric.Sample's inputs
// but keeps the script declarative.
type Sample struct {
	Quality  float64
	Score    float64
	Liveness float64
	Reason   string
}

func NewScriptedChallenger() *ScriptedChallenger {
	return &ScriptedChallenger{
		script: map[model.OperatorID]map[string][]Sample{},
		used:   map[string]int{},
	}
}

// Script queues samples for (op, modality).
func (c *ScriptedChallenger) Script(op model.OperatorID, modality string, samples ...Sample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.script[op]
	if m == nil {
		m = map[string][]Sample{}
		c.script[op] = m
	}
	m[modality] = append(m[modality], samples...)
}

// Next consumes the next scripted sample for (op, modality), or returns a
// no-capture abstention if the script is exhausted.
func (c *ScriptedChallenger) Next(op model.OperatorID, modality string) Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := string(op) + "|" + modality
	m := c.script[op]
	if m == nil || len(m[modality]) == 0 {
		return Sample{Reason: "no_capture"}
	}
	s := m[modality][0]
	m[modality] = m[modality][1:]
	c.used[key]++
	return s
}

// FobSource is a convenience for feeding presence observations in tests/demo.
type FobSource struct {
	Tracker  *presence.Tracker
	mu       sync.Mutex
	counters map[string]uint64
}

func NewFobSource(t *presence.Tracker) *FobSource {
	return &FobSource{Tracker: t, counters: map[string]uint64{}}
}

// Advertise sends one on-body observation for fob at rssi, auto-incrementing the
// replay counter.
func (f *FobSource) Advertise(fobID string, rssi int, at time.Time) error {
	f.mu.Lock()
	f.counters[fobID]++
	c := f.counters[fobID]
	f.mu.Unlock()
	return f.Tracker.Observe(presence.Observation{
		FobID: fobID, ReaderID: "cab-1-reader", RSSI: rssi, Counter: c,
		OnBody: true, At: at,
	})
}
