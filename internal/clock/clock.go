// Package clock abstracts wall-clock time so that presence leases, session
// deadlines and weighing windows can be driven deterministically in tests and
// replayed during audits.
package clock

import (
	"sync"
	"time"
)

// Clock is the only source of "now" for policy decisions.
type Clock interface {
	Now() time.Time
}

// Real is the production clock.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Fake is a manually advanced clock for tests and scenario playback.
type Fake struct {
	mu sync.Mutex
	t  time.Time
}

func NewFake(t time.Time) *Fake { return &Fake{t: t} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}
