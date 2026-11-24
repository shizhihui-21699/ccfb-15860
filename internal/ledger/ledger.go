// Package ledger implements the append-only, hash-chained, signed event log
// that every cabinet controller keeps locally. It is the system of record for
// an audit: the log must be sufficient to reconstruct who was present, when a
// lock opened, what was removed and what the scale measured — with no gaps and
// no silent edits.
//
// Threat model for this package: the attacker has physical access to the
// controller's storage (or restores an old backup) and wants to erase or
// rewrite evidence. Defences:
//
//   - every record carries a SHA-256 hash over its fields and the previous
//     record's hash, so any edit or deletion breaks the chain;
//   - every record is signed with a per-device Ed25519 key, so records cannot
//     be forged by an attacker who rewrites the whole file without the key;
//   - checkpoints seal (seq, head hash, record count) so a truncated copy is
//     detectable against the HQ high-water mark;
//   - Verify detects gaps, reordering, duplicated sequence numbers and
//     divergent branches (two records claiming the same predecessor).
package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Kind names a ledger event. New kinds may be added; readers must tolerate
// unknown kinds rather than failing the chain.
type Kind string

const (
	KindDeviceBoot     Kind = "device.boot"
	KindCheckpoint     Kind = "ledger.checkpoint"
	KindOperatorEnroll Kind = "operator.enrolled"
	KindSessionOpen    Kind = "session.open"
	KindAuthAttempt    Kind = "auth.attempt"
	KindAuthGranted    Kind = "auth.granted"
	KindPresenceLost   Kind = "presence.lost"
	KindPresenceResume Kind = "presence.resume"
	KindSessionArmed   Kind = "session.armed"
	KindUnlock         Kind = "lock.unlocked"
	KindRelock         Kind = "lock.relocked"
	KindDoorOpen       Kind = "door.opened"
	KindDoorClose      Kind = "door.closed"
	KindItemScanned    Kind = "item.scanned"
	KindWeigh          Kind = "weigh.recorded"
	KindSessionClose   Kind = "session.closed"
	KindReconcile      Kind = "session.reconciled"
	KindDiscrepancy    Kind = "discrepancy.raised"
	KindDiscrepancyRes Kind = "discrepancy.cleared"
	KindSyncBatch      Kind = "sync.batch"
	KindClockSkew      Kind = "clock.skew"
	KindDegraded       Kind = "system.degraded"
)

// Record is one entry in the chain. Payload is opaque to the ledger; callers
// marshal typed structs into it. The bytes of Payload are part of the hash, so
// a payload is sealed at append time.
type Record struct {
	Version   int             `json:"v"`
	DeviceID  string          `json:"device"`
	Seq       uint64          `json:"seq"`
	At        time.Time       `json:"at"`
	Kind      Kind            `json:"kind"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	PrevHash  string          `json:"prev,omitempty"`
	Hash      string          `json:"hash"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"sig"`
}

// SignedBytes is the canonical preimage of a record's hash. It deliberately
// excludes Hash and Signature.
func SignedBytes(r Record) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "hazmat-ledger/v%d\n", r.Version)
	fmt.Fprintf(h, "device=%s\n", r.DeviceID)
	fmt.Fprintf(h, "seq=%d\n", r.Seq)
	fmt.Fprintf(h, "at=%d\n", r.At.UnixNano())
	fmt.Fprintf(h, "kind=%s\n", r.Kind)
	fmt.Fprintf(h, "prev=%s\n", r.PrevHash)
	fmt.Fprintf(h, "key=%s\n", r.KeyID)
	h.Write(r.Payload)
	return h.Sum(nil)
}

// computeHash returns the hex hash of a record's canonical bytes.
func computeHash(r Record) string {
	return hex.EncodeToString(SignedBytes(r))
}

// Sign fills Hash and Signature in place. The record must already have its
// Version, DeviceID, Seq, At, Kind, Payload, PrevHash and KeyID set.
func Sign(r *Record, keyID string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("ledger: invalid private key")
	}
	r.Version = FormatVersion
	r.KeyID = keyID
	r.Hash = computeHash(*r)
	r.Signature = hex.EncodeToString(ed25519.Sign(priv, SignedBytes(*r)))
	return nil
}

// FormatVersion is bumped when the canonical preimage changes.
const FormatVersion = 1

// ErrChainBroken is returned by Verify when a record does not chain onto its
// predecessor or a hash does not match its contents.
var ErrChainBroken = errors.New("ledger: chain broken")

// ErrSignature indicates a record's signature does not verify under the
// supplied keyring.
var ErrSignature = errors.New("ledger: invalid signature")

// ErrMissingKey indicates the keyring has no public key for a record's KeyID.
var ErrMissingKey = errors.New("ledger: unknown signing key")

// VerifyChain walks records in order and checks:
//   - sequence numbers are contiguous from 0 (or from the expected base),
//   - each record's prev hash equals the previous record's hash,
//   - each record's hash matches a recomputation of its contents,
//   - each record's signature verifies under keys[KeyID].
//
// It returns the first error with the index of the offending record. VerifyChain
// does not detect truncation of the tail; use a Seal/checkpoint comparison for
// that.
func VerifyChain(records []Record, keys Keyring) error {
	if len(records) == 0 {
		return nil
	}
	first := records[0]
	if first.Seq == 0 && first.PrevHash != "" {
		return fmt.Errorf("%w: record 0 has a predecessor hash", ErrChainBroken)
	}
	// A device that has been running a while may sync only a suffix; the first
	// record of a suffix must still carry a non-empty prev hash, which is the
	// caller's job to anchor. We only enforce internal consistency here, plus
	// that all records come from one device.
	dev := first.DeviceID
	for i, r := range records {
		if r.DeviceID != dev {
			return fmt.Errorf("%w: record %d device %q != %q", ErrChainBroken, i, r.DeviceID, dev)
		}
		if i > 0 {
			prev := records[i-1]
			if r.Seq != prev.Seq+1 {
				return fmt.Errorf("%w: record %d seq %d does not follow %d", ErrChainBroken, i, r.Seq, prev.Seq)
			}
			if r.PrevHash != prev.Hash {
				return fmt.Errorf("%w: record %d prev %s != %s", ErrChainBroken, i, r.PrevHash, prev.Hash)
			}
		}
		if got := computeHash(r); got != r.Hash {
			return fmt.Errorf("%w: record %d hash mismatch (stored %s, computed %s)", ErrChainBroken, i, r.Hash, got)
		}
		pub, ok := keys[r.KeyID]
		if !ok {
			return fmt.Errorf("%w: record %d key %q", ErrMissingKey, i, r.KeyID)
		}
		sig, err := hex.DecodeString(r.Signature)
		if err != nil {
			return fmt.Errorf("%w: record %d bad hex: %v", ErrSignature, i, err)
		}
		if !ed25519.Verify(pub, SignedBytes(r), sig) {
			return fmt.Errorf("%w: record %d", ErrSignature, i)
		}
	}
	return nil
}

// Keyring maps key IDs to verification keys.
type Keyring map[string]ed25519.PublicKey

// Batch is a prefix of one device's log shipped to HQ. It carries the device's
// signed seal at the time of packaging, so HQ can detect a rollback (short log)
// or fork (same seq, different hash) even if earlier batches were lost.
type Batch struct {
	DeviceID  string   `json:"device"`
	KeyID     string   `json:"key_id"`
	BootCount uint64   `json:"boot_count"`
	Records   []Record `json:"records"`
	Seal      Seal     `json:"seal"`
}
