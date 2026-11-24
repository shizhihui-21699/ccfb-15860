package ledger

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"hazmatcontrol/internal/clock"
)

// Store is the durable backing for a Log. Implementations must make Append
// atomic with respect to a single writer and must never rewrite earlier
// records. Append must return only after the bytes are on stable storage,
// because the log is the legal record of a highly-toxic withdrawal.
type Store interface {
	// Load returns all records currently persisted, in order.
	Load() ([]Record, error)
	// Append durably writes one record at the end of the log.
	Append(r Record) error
	// Close releases any resources.
	Close() error
}

// ErrLogCorrupt is returned when the persisted records fail chain or
// signature verification at startup.
var ErrLogCorrupt = errors.New("ledger: persisted log failed verification")

// Log is a single device's append-only ledger. It is safe for concurrent use.
type Log struct {
	mu      sync.Mutex
	device  string
	keyID   string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	clk     clock.Clock
	store   Store
	records []Record
	head    Record
}

// Open loads and verifies an existing store, then returns a Log positioned to
// append. Verification uses keys, which must contain this device's KeyID.
func Open(device, keyID string, priv ed25519.PrivateKey, keys Keyring, store Store, clk clock.Clock) (*Log, error) {
	recs, err := store.Load()
	if err != nil {
		return nil, err
	}
	if err := VerifyChain(recs, keys); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogCorrupt, err)
	}
	privCopy := make(ed25519.PrivateKey, len(priv))
	copy(privCopy, priv)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("ledger: private key has no public part")
	}
	l := &Log{device: device, keyID: keyID, priv: privCopy, pub: pub, clk: clk, store: store, records: recs}
	if len(recs) > 0 {
		l.head = recs[len(recs)-1]
	}
	return l, nil
}

// DeviceID returns the owning device.
func (l *Log) DeviceID() string { return l.device }

// PublicKey returns the verification key this log signs with.
func (l *Log) PublicKey() ed25519.PublicKey { return l.pub }

// Head returns a copy of the most recent record.
func (l *Log) Head() Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Len returns the number of records.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}

// Records returns a copy of all records.
func (l *Log) Records() []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Record, len(l.records))
	copy(out, l.records)
	return out
}

// RecordsFrom returns a copy of records with Seq >= fromSeq.
func (l *Log) RecordsFrom(fromSeq uint64) []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Record, 0, 16)
	for _, r := range l.records {
		if r.Seq >= fromSeq {
			out = append(out, r)
		}
	}
	return out
}

// Append signs and durably appends one event. It assigns Seq, At, PrevHash and
// only then persists, so a crash either loses the tail record entirely or keeps
// a fully valid one.
func (l *Log) Append(kind Kind, payload any) (Record, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Record{}, fmt.Errorf("ledger: marshal payload: %w", err)
	}
	return l.AppendRaw(kind, raw)
}

// AppendRaw is Append with a pre-encoded payload.
func (l *Log) AppendRaw(kind Kind, raw json.RawMessage) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := Record{
		Version:  FormatVersion,
		DeviceID: l.device,
		Seq:      l.head.Seq + 1,
		At:       l.clk.Now().UTC(),
		Kind:     kind,
		Payload:  raw,
		PrevHash: l.head.Hash,
	}
	if len(l.records) == 0 {
		rec.Seq = 0
		rec.PrevHash = ""
	}
	if err := Sign(&rec, l.keyID, l.priv); err != nil {
		return Record{}, err
	}
	if err := l.store.Append(rec); err != nil {
		return Record{}, fmt.Errorf("ledger: persist: %w", err)
	}
	l.records = append(l.records, rec)
	l.head = rec
	return rec, nil
}

// Seal is a signed high-water mark over the log. It proves at least Seq
// records existed and that the chain at Seq has a particular hash. HQ stores
// the latest seal per device; any later sync that presents a shorter chain or a
// different hash at the same seq is a rollback or a fork.
type Seal struct {
	DeviceID string    `json:"device"`
	Seq      uint64    `json:"seq"`
	Count    uint64    `json:"count"`
	HeadHash string    `json:"head_hash"`
	At       time.Time `json:"at"`
	KeyID    string    `json:"key_id"`
	Sig      string    `json:"sig"`
}

func sealBytes(s Seal) []byte {
	b := make([]byte, 0, 256)
	b = append(b, "hazmat-seal/v1\n"...)
	b = append(b, s.DeviceID...)
	b = append(b, '\n')
	b = append(b, fmt.Sprintf("%d\n%d\n%s\n%d\n%s\n", s.Seq, s.Count, s.HeadHash, s.At.UnixNano(), s.KeyID)...)
	return b
}

// Seal produces a signed high-water mark covering all records appended so far.
func (l *Log) Seal() Seal {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Seal{
		DeviceID: l.device,
		Seq:      l.head.Seq,
		Count:    uint64(len(l.records)),
		HeadHash: l.head.Hash,
		At:       l.clk.Now().UTC(),
		KeyID:    l.keyID,
	}
	if len(l.records) == 0 {
		s.Seq = 0
		s.Count = 0
		s.HeadHash = ""
	}
	s.Sig = hexEncode(ed25519.Sign(l.priv, sealBytes(s)))
	return s
}

// VerifySeal checks a seal's signature against keys.
func VerifySeal(s Seal, keys Keyring) error {
	pub, ok := keys[s.KeyID]
	if !ok {
		return fmt.Errorf("%w: seal key %q", ErrMissingKey, s.KeyID)
	}
	sig, err := hexDecode(s.Sig)
	if err != nil {
		return fmt.Errorf("%w: seal hex: %v", ErrSignature, err)
	}
	if !ed25519.Verify(pub, sealBytes(s), sig) {
		return ErrSignature
	}
	return nil
}

// CheckAgainstSeal reports whether records are consistent with a previously
// trusted seal: the chain must reach at least s.Seq and, if it does, the record
// at s.Seq must have s.HeadHash. Records with Seq < s.Seq are verified too, so
// a rewrite of history is caught even when the new tail is longer.
func CheckAgainstSeal(records []Record, s Seal) error {
	if len(records) == 0 {
		if s.Seq == 0 && s.Count == 0 {
			return nil
		}
		return fmt.Errorf("%w: empty log but seal claims seq %d", ErrChainBroken, s.Seq)
	}
	if s.Count == 0 {
		return nil
	}
	var found *Record
	for i := range records {
		if records[i].Seq == s.Seq {
			found = &records[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("%w: log ends before sealed seq %d", ErrChainBroken, s.Seq)
	}
	if found.Hash != s.HeadHash {
		return fmt.Errorf("%w: sealed head %s at seq %d but log has %s", ErrChainBroken, s.HeadHash, s.Seq, found.Hash)
	}
	return nil
}

// AppendCheckpoint writes a self-sealing checkpoint record whose payload is the
// head at the time of writing. It gives auditors periodic anchors even if the
// external seal is lost.
func (l *Log) AppendCheckpoint() (Record, error) {
	l.mu.Lock()
	h := l.head
	n := uint64(len(l.records))
	l.mu.Unlock()
	return l.Append(KindCheckpoint, map[string]any{
		"head_seq":  h.Seq,
		"head_hash": h.Hash,
		"count":     n,
	})
}

// ---- In-memory store -------------------------------------------------------

// MemStore is an in-memory Store for tests and the demo.
type MemStore struct {
	mu   sync.Mutex
	recs []Record
}

func NewMemStore() *MemStore { return &MemStore{} }

func (m *MemStore) Load() ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.recs))
	copy(out, m.recs)
	return out, nil
}

func (m *MemStore) Append(r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, r)
	return nil
}

func (m *MemStore) Close() error { return nil }

// Clone returns an independent copy, used by tests to simulate a stolen or
// tampered disk image.
func (m *MemStore) Clone() *MemStore {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &MemStore{recs: make([]Record, len(m.recs))}
	copy(out.recs, m.recs)
	return out
}

// Mutate applies fn to the stored records directly, bypassing signing. Only for
// demonstrating tamper detection in tests.
func (m *MemStore) Mutate(fn func(recs []Record) []Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = fn(m.recs)
}

// ---- File store ------------------------------------------------------------

// FileStore persists records as newline-delimited JSON and fsyncs after each
// append. It refuses to truncate or rewrite.
type FileStore struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// OpenFileStore opens or creates path in append-only mode.
func OpenFileStore(path string) (*FileStore, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &FileStore{path: path, f: f}, nil
}

func (fs *FileStore) Load() ([]Record, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if _, err := fs.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var out []Record
	sc := bufio.NewScanner(fs.f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("ledger: %s line %d: %w", fs.path, line+1, err)
		}
		out = append(out, r)
		line++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if _, err := fs.f.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	return out, nil
}

func (fs *FileStore) Append(r Record) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := fs.f.Write(b); err != nil {
		return err
	}
	return fs.f.Sync()
}

func (fs *FileStore) Close() error { return fs.f.Close() }

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil, errors.New("bad hex digit")
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
