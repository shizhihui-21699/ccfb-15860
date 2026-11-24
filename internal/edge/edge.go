// Package edge is the offline-first durability layer for a cabinet controller.
//
// The store floor has poor connectivity, so the controller must be fully
// operable and fully auditable with no network at all. That creates three
// problems that this package handles explicitly:
//
//  1. Evidence must survive a crash or power cut. Every event goes to a local
//     fsynced ledger before the lock actuates. The network is never in the
//     critical path.
//
//  2. Evidence must survive a *wipe*. A controller with a corrupt or missing
//     log must not silently restart as a pristine device — that is the simplest
//     way to erase an incident. The controller therefore persists its last
//     signed seal out of band (a small state file) and refuses to come up in
//     normal mode if the log is shorter than the seal claims.
//
//  3. Syncing must be resumable and ordered. Outbound batches are queued
//     durably and only dropped after HQ acknowledges them, so a flaky link
//     cannot lose events or reorder them.
package edge

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/ledger"
)

// ErrRollback is returned by Boot when the local log is shorter than the last
// seal this device wrote. It means the log was deleted, truncated or restored
// from an old backup, and must be resolved by a supervisor with the HQ copy.
var ErrRollback = errors.New("edge: local log is behind the last recorded seal (possible tamper or restore)")

// BootState is the durable state kept alongside the log.
type BootState struct {
	DeviceID    string      `json:"device"`
	Seal        ledger.Seal `json:"seal"`
	BootCount   uint64      `json:"boot_count"`
	LastSyncSeq uint64      `json:"last_sync_seq"`
	HaveSync    bool        `json:"have_sync"`
}

// StateFile persists the seal and boot counter across restarts. Writes are
// atomic (write-temp, fsync, rename) so a power cut never leaves a torn file.
type StateFile struct {
	path string
}

func NewStateFile(path string) *StateFile { return &StateFile{path: path} }

func (f *StateFile) Load() (BootState, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BootState{}, nil
		}
		return BootState{}, err
	}
	var s BootState
	if err := json.Unmarshal(b, &s); err != nil {
		return BootState{}, fmt.Errorf("edge: corrupt state file %s: %w", f.path, err)
	}
	return s, nil
}

func (f *StateFile) Save(s BootState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(f.path, b)
}

func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Options configures Boot.
type Options struct {
	Device   string
	KeyID    string
	Priv     ed25519.PrivateKey
	Keys     ledger.Keyring
	Store    ledger.Store
	State    *StateFile
	QueueDir string
	Clock    clock.Clock
}

// Controller owns a cabinet's local ledger and its outbound queue.
type Controller struct {
	mu     sync.Mutex
	log    *ledger.Log
	state  *StateFile
	boot   BootState
	clk    clock.Clock
	queue  *Queue
	online bool
	skew   time.Duration
	// Degraded is set when the controller came up without being able to prove
	// its log is a continuation of its own history. Callers must refuse to open
	// cabinets in this state.
	Degraded bool
}

// Boot opens the controller, verifies its log against the persisted seal, and
// records a boot event. If the log is short of the seal it returns ErrRollback
// together with a controller in Degraded mode, so the caller can raise an
// incident while still allowing a supervisor to export evidence.
func Boot(o Options) (*Controller, error) {
	if len(o.Priv) != ed25519.PrivateKeySize {
		return nil, errors.New("edge: Options.Priv must be a valid ed25519.PrivateKey")
	}
	st, err := o.State.Load()
	if err != nil {
		return nil, err
	}
	log, err := ledger.Open(o.Device, o.KeyID, o.Priv, o.Keys, o.Store, o.Clock)
	if err != nil {
		return nil, err
	}
	q, err := OpenQueue(o.QueueDir)
	if err != nil {
		return nil, err
	}
	c := &Controller{log: log, state: o.State, boot: st, clk: o.Clock, queue: q}
	c.boot.DeviceID = o.Device
	c.boot.BootCount++

	rollback := false
	if st.Seal.Count > 0 {
		if err := ledger.CheckAgainstSeal(log.Records(), st.Seal); err != nil {
			c.Degraded = true
			rollback = true
		}
	}
	// Record the boot itself. Even in rollback mode we append, so the new boot
	// is evidence; the degraded flag stops the caller from opening cabinets.
	if _, err := c.log.Append(ledger.KindDeviceBoot, map[string]any{
		"boot_count":    c.boot.BootCount,
		"degraded":      c.Degraded,
		"prev_seal_seq": st.Seal.Seq,
		"log_len":       log.Len(),
	}); err != nil {
		return nil, err
	}
	if err := c.persistState(); err != nil {
		return nil, err
	}
	if rollback {
		return c, ErrRollback
	}
	return c, nil
}

// Ledger exposes the underlying log (read-mostly).
func (c *Controller) Ledger() *ledger.Log { return c.log }

// Queue exposes the outbound queue.
func (c *Controller) Queue() *Queue { return c.queue }

// SetOnline adjusts the transport state; callers wire this to a connectivity
// probe. Offline is the normal state, not an error.
func (c *Controller) SetOnline(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.online = v
}

// Online reports the last transport state.
func (c *Controller) Online() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online
}

// Record appends an event. It never fails because of the network.
func (c *Controller) Record(kind ledger.Kind, payload any) (ledger.Record, error) {
	return c.log.Append(kind, payload)
}

// persistState saves the seal and counters. It is called after boot, after each
// checkpoint and after each acknowledged sync.
func (c *Controller) persistState() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.boot.Seal = c.log.Seal()
	return c.state.Save(c.boot)
}

// Checkpoint seals the current head durably. Call after any security-relevant
// event; the seal is what makes truncation detectable later.
func (c *Controller) Checkpoint() error {
	if _, err := c.log.AppendCheckpoint(); err != nil {
		return err
	}
	return c.persistState()
}

// EnqueueBatch packages unsynced records since the last acknowledged seq into
// the queue with a fresh seal. It is idempotent: calling it twice without a sync
// just refreshes the pending batch.
func (c *Controller) EnqueueBatch() (ledger.Batch, error) {
	c.mu.Lock()
	from := c.boot.LastSyncSeq
	haveSync := c.boot.HaveSync
	device := c.log.DeviceID()
	bootCount := c.boot.BootCount
	c.mu.Unlock()

	if !haveSync {
		from = 0
	}
	recs := c.log.RecordsFrom(from)
	b := ledger.Batch{
		DeviceID:  device,
		KeyID:     c.log.Seal().KeyID,
		BootCount: bootCount,
		Records:   recs,
		Seal:      c.log.Seal(),
	}
	if len(recs) == 0 {
		return b, nil
	}
	if err := c.queue.Put(b); err != nil {
		return b, err
	}
	return b, nil
}

// AckBatch records HQ's acknowledgement of a batch, advancing LastSyncSeq and
// dropping the batch from the queue. The state is saved before the queue entry
// is removed, so a crash between the two replays a batch rather than losing it.
func (c *Controller) AckBatch(lastSeq uint64) error {
	c.mu.Lock()
	if lastSeq <= c.boot.LastSyncSeq && c.boot.HaveSync {
		c.mu.Unlock()
		return c.queue.DropUpTo(lastSeq)
	}
	c.boot.LastSyncSeq = lastSeq
	c.boot.HaveSync = true
	c.boot.Seal = c.log.Seal()
	err := c.state.Save(c.boot)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.queue.DropUpTo(lastSeq)
}

// ClockSkew returns the largest forward skew observed from fobs or the network.
func (c *Controller) ClockSkew() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.skew
}

// NoteSkew records an observed skew for display; it never changes the clock.
func (c *Controller) NoteSkew(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > c.skew {
		c.skew = d
	}
}

// ---- Outbound queue --------------------------------------------------------

// Queue is a durable FIFO of batches awaiting acknowledgement.
type Queue struct {
	mu      sync.Mutex
	dir     string
	path    string
	batches []ledger.Batch
}

func OpenQueue(dir string) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, path: filepath.Join(dir, "outbox.json")}
	b, err := os.ReadFile(q.path)
	if err == nil {
		if err := json.Unmarshal(b, &q.batches); err != nil {
			return nil, fmt.Errorf("edge: corrupt outbox %s: %w", q.path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return q, nil
}

func (q *Queue) Put(b ledger.Batch) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	// Replace any pending batch for the same device: a later batch supersedes an
	// earlier one because it carries a longer prefix and a newer seal.
	for i := range q.batches {
		if q.batches[i].DeviceID == b.DeviceID {
			q.batches[i] = b
			return q.flush()
		}
	}
	q.batches = append(q.batches, b)
	return q.flush()
}

// DropUpTo removes batches whose highest record seq is <= lastSeq.
func (q *Queue) DropUpTo(lastSeq uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	kept := q.batches[:0]
	for _, b := range q.batches {
		var maxSeq uint64
		if len(b.Records) > 0 {
			maxSeq = b.Records[len(b.Records)-1].Seq
		}
		if maxSeq > lastSeq {
			kept = append(kept, b)
		}
	}
	q.batches = kept
	return q.flush()
}

// Pending returns a copy of queued batches.
func (q *Queue) Pending() []ledger.Batch {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]ledger.Batch, len(q.batches))
	copy(out, q.batches)
	return out
}

func (q *Queue) flush() error {
	b, err := json.MarshalIndent(q.batches, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(q.path, b)
}
