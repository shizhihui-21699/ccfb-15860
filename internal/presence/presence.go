// Package presence turns raw cabinet-reader observations into *continuous*
// co-presence: the assertion that two specific operators are both physically at
// the cabinet, right now, as two distinct bodies.
//
// This package exists because a badge swipe is not presence. The two attack
// patterns the business reported both defeat one-shot verification:
//
//  1. Badge sharing — one person presents a colleague's badge and completes
//     "two-person" verification alone.
//  2. Collusion-then-abandon — two people authenticate together, then one
//     leaves and the other keeps withdrawing.
//
// Both are defeated the same way: presence must be *live and continuous* for
// the whole withdrawal, and it must be attributable to *two distinct bodies*.
// The controller therefore requires each operator to carry an on-body fob that
// advertises continuously with a monotonic counter, an on-body sensor, and
// tamper reporting. A lease lapses the instant heartbeats stop, the fob leaves
// the reader zone, is reported off-body, or is reported tampered. The session
// layer revokes immediately when a lease lapses.
package presence

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/model"
)

// Config is the reader-zone geometry and timing policy for one cabinet.
type Config struct {
	// MinRSSI is the weakest signal still considered "at the cabinet".
	MinRSSI int
	// MaxGap is the longest silence tolerated before a lease lapses. It must be
	// several times the fob's advertising interval, with margin for RF loss.
	MaxGap time.Duration
	// Window bounds how much history is kept for correlation analysis.
	Window time.Duration
	// SameBodyCorrelation is the Pearson correlation of two fobs' RSSI series
	// above which we suspect both fobs are on one person.
	SameBodyCorrelation float64
	// MinCorrelationSamples is the number of paired time buckets required before
	// correlation is trusted.
	MinCorrelationSamples int
}

// DefaultConfig is a sane starting point for a steel-and-concrete chemical
// store with heavy RF attenuation.
func DefaultConfig() Config {
	return Config{
		MinRSSI:               -78,
		MaxGap:                12 * time.Second,
		Window:                90 * time.Second,
		SameBodyCorrelation:   0.82,
		MinCorrelationSamples: 6,
	}
}

// Observation is one advertisement or sensor report from a fob, as received by
// a cabinet reader. Counter is a monotonically increasing per-fob sequence
// number used to reject replays; OnBody reflects capacitive/wrist-motion
// confirmation that the fob is being worn; Tampered is set by the fob when its
// strap is cut or its enclosure opened.
type Observation struct {
	FobID    string
	ReaderID string
	RSSI     int
	Counter  uint64
	OnBody   bool
	Tampered bool
	At       time.Time
}

// Presence is the evaluated state of one operator.
type Presence struct {
	Operator model.OperatorID
	FobID    string
	Live     bool
	Reason   string
	LastAt   time.Time
	Since    time.Time
	RSSI     int
}

// CoPresence is the evaluated two-operator state.
type CoPresence struct {
	OK        bool
	Reason    string
	A, B      Presence
	Suspicion float64
	// SameBody is true when the readings are statistically consistent with both
	// fobs riding on one person. Callers must not treat this as proof; it is a
	// trigger for a distinctness challenge.
	SameBody bool
}

// fobBinding ties a fob to its enrolled operator.
type fobBinding struct {
	operator model.OperatorID
	token    string // provisioning token; fobs with the zero token are unbound
}

type fobState struct {
	obs        []Observation
	lastAt     time.Time
	firstAt    time.Time
	lastRSSI   int
	onBody     bool
	tampered   bool
	counter    uint64
	sawCounter bool
}

// Tracker evaluates presence. It is safe for concurrent use.
type Tracker struct {
	mu        sync.Mutex
	cfg       Config
	clk       clock.Clock
	fobs      map[string]*fobState
	bind      map[string]fobBinding
	byOp      map[model.OperatorID]string
	clockSkew time.Duration
}

// NewTracker builds a tracker with cfg and clk.
func NewTracker(cfg Config, clk clock.Clock) *Tracker {
	return &Tracker{
		cfg:  cfg,
		clk:  clk,
		fobs: make(map[string]*fobState),
		bind: make(map[string]fobBinding),
		byOp: make(map[model.OperatorID]string),
	}
}

// BindFob associates a fob with an operator. Re-binding a fob that is already
// bound to another operator is refused: a fob is one person's.
func (t *Tracker) BindFob(op model.OperatorID, fobID, token string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if b, ok := t.bind[fobID]; ok && b.token != "" && b.token != token {
		return fmt.Errorf("presence: fob %s already bound to %s", fobID, b.operator)
	}
	if cur, ok := t.byOp[op]; ok && cur != fobID {
		return fmt.Errorf("presence: operator %s already has fob %s", op, cur)
	}
	t.bind[fobID] = fobBinding{operator: op, token: token}
	t.byOp[op] = fobID
	return nil
}

// FobOf returns the fob bound to op, or "".
func (t *Tracker) FobOf(op model.OperatorID) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byOp[op]
}

// Observe records an advertisement. It rejects observations for unbound fobs,
// counter regressions (replay), and observations timestamped unreasonably far in
// the future (a fob with a wrong clock cannot extend a lease).
func (t *Tracker) Observe(o Observation) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.bind[o.FobID]
	if !ok || b.operator == "" {
		return fmt.Errorf("presence: unbound fob %s", o.FobID)
	}
	now := t.clk.Now()
	if o.At.IsZero() {
		o.At = now
	}
	if o.At.After(now.Add(5 * time.Second)) {
		// Clock skew on the reader or fob; clamp rather than trust the future.
		if o.At.Sub(now) > t.clockSkew {
			t.clockSkew = o.At.Sub(now)
		}
		o.At = now
	}
	st := t.fobs[o.FobID]
	if st == nil {
		st = &fobState{}
		t.fobs[o.FobID] = st
	}
	if st.sawCounter && o.Counter <= st.counter {
		return fmt.Errorf("presence: replay or stale counter for fob %s (%d <= %d)", o.FobID, o.Counter, st.counter)
	}
	if st.tampered {
		// Once tampered, a fob stays untrusted until re-provisioned.
		return fmt.Errorf("presence: fob %s is flagged tampered", o.FobID)
	}
	st.counter = o.Counter
	st.sawCounter = true
	st.lastAt = o.At
	st.lastRSSI = o.RSSI
	st.onBody = o.OnBody
	st.tampered = o.Tampered
	if st.firstAt.IsZero() {
		st.firstAt = o.At
	}
	st.obs = append(st.obs, o)
	// Prune history outside the correlation window.
	cut := now.Add(-t.cfg.Window)
	i := 0
	for i < len(st.obs) && st.obs[i].At.Before(cut) {
		i++
	}
	if i > 0 {
		st.obs = append(st.obs[:0], st.obs[i:]...)
	}
	return nil
}

// Status evaluates one operator's presence at the current instant.
func (t *Tracker) Status(op model.OperatorID) Presence {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.statusLocked(op)
}

func (t *Tracker) statusLocked(op model.OperatorID) Presence {
	p := Presence{Operator: op}
	fobID, bound := t.byOp[op]
	if !bound {
		p.Reason = "no fob bound to operator"
		return p
	}
	p.FobID = fobID
	st := t.fobs[fobID]
	if st == nil || st.lastAt.IsZero() {
		p.Reason = "no presence signal"
		return p
	}
	now := t.clk.Now()
	p.LastAt = st.lastAt
	p.Since = st.firstAt
	p.RSSI = st.lastRSSI
	if st.tampered {
		p.Reason = "fob tamper detected"
		return p
	}
	if !st.onBody {
		p.Reason = "fob not detected on body"
		return p
	}
	if gap := now.Sub(st.lastAt); gap > t.cfg.MaxGap {
		p.Reason = fmt.Sprintf("presence lease expired (%s since last signal, max %s)", gap.Round(time.Second), t.cfg.MaxGap)
		return p
	}
	if st.lastRSSI < t.cfg.MinRSSI {
		p.Reason = fmt.Sprintf("fob outside cabinet zone (rssi %d < %d)", st.lastRSSI, t.cfg.MinRSSI)
		return p
	}
	p.Live = true
	p.Reason = "live"
	return p
}

// CoPresence evaluates whether both operators are live and distinct.
func (t *Tracker) CoPresence(a, b model.OperatorID) CoPresence {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := CoPresence{}
	if a == b {
		out.Reason = "both slots name the same operator"
		return out
	}
	out.A = t.statusLocked(a)
	out.B = t.statusLocked(b)
	if !out.A.Live {
		out.Reason = fmt.Sprintf("operator %s not present: %s", a, out.A.Reason)
		return out
	}
	if !out.B.Live {
		out.Reason = fmt.Sprintf("operator %s not present: %s", b, out.B.Reason)
		return out
	}
	if out.A.FobID == out.B.FobID {
		out.Reason = "both operators report the same fob"
		return out
	}
	out.Suspicion = t.correlationLocked(out.A.FobID, out.B.FobID)
	if out.Suspicion >= t.cfg.SameBodyCorrelation {
		out.SameBody = true
		out.Reason = fmt.Sprintf("fob signals are correlated (r=%.2f): possible same-body carry", out.Suspicion)
		// Still OK at this layer; the access layer demands a distinctness proof.
	}
	out.OK = true
	return out
}

// correlationLocked buckets both fobs' RSSI series into one-second buckets and
// returns the Pearson correlation of the paired buckets. Two fobs on the same
// torso shadow each other and track together; two people standing apart, even
// side by side, do not track this closely.
func (t *Tracker) correlationLocked(fobA, fobB string) float64 {
	a, b := t.fobs[fobA], t.fobs[fobB]
	if a == nil || b == nil {
		return 0
	}
	sa := bucketRSSI(a.obs)
	sb := bucketRSSI(b.obs)
	pairs := make([][2]float64, 0, len(sa))
	for k, va := range sa {
		if vb, ok := sb[k]; ok {
			pairs = append(pairs, [2]float64{va, vb})
		}
	}
	if len(pairs) < t.cfg.MinCorrelationSamples {
		return 0
	}
	// No sort: the buckets are already paired by timestamp key, and sorting by
	// value (as an earlier version did) destroys the time alignment correlation
	// depends on.
	return pearson(pairs)
}

// bucketRSSI averages RSSI per one-second bucket keyed by Unix second, which
// only makes sense within one cabinet's reader zone.
func bucketRSSI(obs []Observation) map[int64]float64 {
	sum := make(map[int64]float64)
	n := make(map[int64]int)
	for _, o := range obs {
		k := o.At.Unix()
		sum[k] += float64(o.RSSI)
		n[k]++
	}
	out := make(map[int64]float64, len(sum))
	for k, v := range sum {
		out[k] = v / float64(n[k])
	}
	return out
}

func pearson(pairs [][2]float64) float64 {
	// Center before summing. RSSI values sit near -50 with only a few dB of
	// variance, so the textbook one-pass formula (n*sxy - sx*sy) suffers
	// catastrophic cancellation and reports ~0 even for identical series.
	n := float64(len(pairs))
	var mx, my float64
	for _, p := range pairs {
		mx += p[0]
		my += p[1]
	}
	mx /= n
	my /= n
	var sxx, syy, sxy float64
	for _, p := range pairs {
		dx := p[0] - mx
		dy := p[1] - my
		sxx += dx * dx
		syy += dy * dy
		sxy += dx * dy
	}
	den := math.Sqrt(sxx * syy)
	if den <= 1e-9 {
		return 0
	}
	return sxy / den
}

// Snapshot returns the current presence of every bound operator, for the
// operator console and for periodic ledger checkpoints.
func (t *Tracker) Snapshot() []Presence {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Presence, 0, len(t.byOp))
	for op := range t.byOp {
		out = append(out, t.statusLocked(op))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operator < out[j].Operator })
	return out
}

// ForciblyLapse clears a fob's history. Used when a fob is reported lost or a
// supervisor isolates the cabinet.
func (t *Tracker) ForciblyLapse(fobID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if st, ok := t.fobs[fobID]; ok {
		st.obs = nil
		st.lastAt = time.Time{}
		st.onBody = false
	}
}
