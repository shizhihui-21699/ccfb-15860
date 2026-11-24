// Package hq is the headquarters ingest and audit service. Controllers sync
// batches here whenever they have connectivity; HQ is never in the withdrawal
// critical path, but it is the system of record for cross-device audit.
//
// HQ's job is to be hard to fool with a controller that is lying, was restored
// from a backup, or is replaying old traffic:
//
//   - every record is signature- and chain-verified on ingest;
//   - per device it keeps the highest trusted seal, and rejects any batch whose
//     seal is older (rollback) or whose hash at a sealed seq differs (fork);
//   - a batch must chain onto what HQ already holds, or start before HQ's first
//     held record and overlap it, so a suffix with a forged predecessor is
//     caught;
//   - replay of already-held records is idempotent.
package hq

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"hazmatcontrol/internal/ledger"
)

// ErrRollback: the batch's seal is behind what HQ has already trusted.
var ErrRollback = errors.New("hq: batch seal is older than the trusted seal (rollback)")

// ErrFork: the batch disagrees with trusted history at the same sequence.
var ErrFork = errors.New("hq: batch diverges from trusted history at a sealed sequence")

// ErrUnanchored: the batch neither chains onto held records nor overlaps them,
// so its predecessor hash cannot be trusted.
var ErrUnanchored = errors.New("hq: batch does not chain onto or overlap trusted history")

// ErrBadSignature: a record or seal failed verification.
var ErrBadSignature = errors.New("hq: signature verification failed")

// Status is a device's ingest state.
type Status struct {
	DeviceID    string
	HeadSeq     uint64
	HeadHash    string
	Count       int
	LastSealSeq uint64
	LastSeen    time.Time
	BootCount   uint64
	Degraded    bool
	Incidents   []string
}

// Ingest accepts and verifies batches.
type Ingest struct {
	mu   sync.Mutex
	keys ledger.Keyring
	devs map[string]*deviceState
}

type deviceState struct {
	records   []ledger.Record // full trusted chain, seq-ordered
	bySeq     map[uint64]ledger.Record
	seal      ledger.Seal
	seen      time.Time
	boot      uint64
	incidents []string
	degraded  bool
}

func NewIngest(keys ledger.Keyring) *Ingest {
	return &Ingest{keys: keys, devs: make(map[string]*deviceState)}
}

// Accept ingests a batch. It is idempotent and safe to call with overlapping or
// replayed batches. On a rollback or fork it records an incident and returns the
// error; the caller should alert, not simply retry.
func (h *Ingest) Accept(b ledger.Batch) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 1. Verify the batch's own integrity and signatures.
	if err := ledger.VerifyChain(b.Records, h.keys); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if err := ledger.VerifySeal(b.Seal, h.keys); err != nil {
		return fmt.Errorf("%w: seal: %v", ErrBadSignature, err)
	}
	if b.Seal.DeviceID != b.DeviceID {
		return fmt.Errorf("%w: seal device %q != batch device %q", ErrBadSignature, b.Seal.DeviceID, b.DeviceID)
	}
	for _, r := range b.Records {
		if r.DeviceID != b.DeviceID {
			return fmt.Errorf("%w: record device %q != batch device %q", ErrBadSignature, r.DeviceID, b.DeviceID)
		}
	}

	st := h.devs[b.DeviceID]
	if st == nil {
		st = &deviceState{bySeq: make(map[uint64]ledger.Record)}
		h.devs[b.DeviceID] = st
	}

	// 2. Rollback: a batch sealed below our trusted high-water mark means the
	// device's view went backwards. That is either a restore from backup or a
	// deliberate truncation.
	if st.seal.Count > 0 && b.Seal.Seq < st.seal.Seq {
		st.incidents = append(st.incidents, fmt.Sprintf("rollback at %s: batch seal seq %d < trusted %d", time.Now().UTC().Format(time.RFC3339), b.Seal.Seq, st.seal.Seq))
		st.degraded = true
		return fmt.Errorf("%w: batch seq %d < trusted %d", ErrRollback, b.Seal.Seq, st.seal.Seq)
	}

	// 3. Fork: same seq, different hash anywhere we already hold a record.
	for _, r := range b.Records {
		if have, ok := st.bySeq[r.Seq]; ok && have.Hash != r.Hash {
			st.incidents = append(st.incidents, fmt.Sprintf("fork at %s: seq %d hash %s != trusted %s", time.Now().UTC().Format(time.RFC3339), r.Seq, r.Hash, have.Hash))
			st.degraded = true
			return fmt.Errorf("%w: seq %d", ErrFork, r.Seq)
		}
	}

	// 4. Anchoring. On a device's *first* contact HQ has nothing to check a
	// predecessor against, so it must start at seq 0: otherwise an attacker
	// could truncate the front of the history and present a plausible suffix.
	// A brand-new controller's log begins at 0, so this costs nothing.
	if len(st.records) == 0 {
		if len(b.Records) == 0 {
			return fmt.Errorf("%w: first batch from %s is empty", ErrUnanchored, b.DeviceID)
		}
		if b.Records[0].Seq != 0 {
			return fmt.Errorf("%w: first batch from %s starts at seq %d, want 0", ErrUnanchored, b.DeviceID, b.Records[0].Seq)
		}
	}
	// A batch that starts after our head must chain onto it; a batch that starts
	// at 0 is a full-history resend and is fine; a batch that starts in the
	// middle must overlap a record we hold so its predecessor can be checked.
	if len(b.Records) > 0 && len(st.records) > 0 {
		first := b.Records[0]
		if first.Seq > st.records[len(st.records)-1].Seq+1 {
			return fmt.Errorf("%w: gap; batch starts at %d, held head is %d", ErrUnanchored, first.Seq, st.records[len(st.records)-1].Seq)
		}
		if first.Seq > 0 {
			prev, ok := st.bySeq[first.Seq-1]
			if !ok {
				return fmt.Errorf("%w: batch starts at %d and predecessor is not held", ErrUnanchored, first.Seq)
			}
			if first.PrevHash != prev.Hash {
				st.incidents = append(st.incidents, fmt.Sprintf("disconnected suffix at %s: seq %d prev hash mismatch", time.Now().UTC().Format(time.RFC3339), first.Seq))
				st.degraded = true
				return fmt.Errorf("%w: seq %d predecessor mismatch", ErrFork, first.Seq)
			}
		}
	}

	// 5. Merge into held history (records are already verified and non-divergent).
	added := 0
	for _, r := range b.Records {
		if _, ok := st.bySeq[r.Seq]; ok {
			continue
		}
		st.bySeq[r.Seq] = r
		added++
	}
	if added > 0 || len(st.records) == 0 {
		st.records = st.records[:0]
		seqs := make([]uint64, 0, len(st.bySeq))
		for s := range st.bySeq {
			seqs = append(seqs, s)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for _, s := range seqs {
			st.records = append(st.records, st.bySeq[s])
		}
	}

	if b.Seal.Seq >= st.seal.Seq {
		st.seal = b.Seal
	}
	if b.BootCount > st.boot {
		st.boot = b.BootCount
	}
	st.seen = time.Now().UTC()
	return nil
}

// Status returns a device's ingest state.
func (h *Ingest) Status(device string) (Status, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.devs[device]
	if st == nil {
		return Status{}, false
	}
	s := Status{
		DeviceID: device, Count: len(st.records), LastSealSeq: st.seal.Seq,
		LastSeen: st.seen, BootCount: st.boot, Degraded: st.degraded,
		Incidents: append([]string(nil), st.incidents...),
	}
	if len(st.records) > 0 {
		s.HeadSeq = st.records[len(st.records)-1].Seq
		s.HeadHash = st.records[len(st.records)-1].Hash
	}
	return s, true
}

// Devices lists known device IDs.
func (h *Ingest) Devices() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.devs))
	for d := range h.devs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Export returns the trusted records for a device in seq order.
func (h *Ingest) Export(device string) []ledger.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.devs[device]
	if st == nil {
		return nil
	}
	out := make([]ledger.Record, len(st.records))
	copy(out, st.records)
	return out
}

// AuditExport re-verifies a device's full held history and returns the count.
// The signature check is repeated here so the exported chain is proven at the
// moment of export, not only at ingest.
func (h *Ingest) AuditExport(device string) (int, error) {
	recs := h.Export(device)
	if err := ledger.VerifyChain(recs, h.keys); err != nil {
		return 0, err
	}
	return len(recs), nil
}
