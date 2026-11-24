package edge_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/edge"
	"hazmatcontrol/internal/ledger"
)

func keys(t *testing.T) (ledger.Keyring, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ledger.Keyring{"k1": pub}, priv
}

func openController(t *testing.T, dir string, keys ledger.Keyring, priv ed25519.PrivateKey, store ledger.Store, clk clock.Clock) (*edge.Controller, error) {
	t.Helper()
	return edge.Boot(edge.Options{
		Device: "cab-1", KeyID: "k1", Priv: priv, Keys: keys,
		Store: store, State: edge.NewStateFile(filepath.Join(dir, "state.json")),
		QueueDir: filepath.Join(dir, "outbox"), Clock: clk,
	})
}

// A controller must fully operate and build evidence with no network at all,
// then sync the whole backlog when connectivity returns.
func TestOfflineThenSync(t *testing.T) {
	dir := t.TempDir()
	ks, priv := keys(t)
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	store := ledger.NewMemStore()

	c, err := openController(t, dir, ks, priv, store, clk)
	if err != nil {
		t.Fatal(err)
	}
	c.SetOnline(false)
	for i := 0; i < 10; i++ {
		if _, err := c.Record(ledger.KindWeigh, map[string]any{"n": i}); err != nil {
			t.Fatalf("offline record %d failed: %v", i, err)
		}
	}
	if c.Ledger().Len() != 11 { // boot + 10
		t.Fatalf("ledger len = %d, want 11", c.Ledger().Len())
	}
	// Enqueue while offline: the batch is durable in the outbox.
	b, err := c.EnqueueBatch()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Records) != 11 {
		t.Fatalf("batch has %d records, want 11", len(b.Records))
	}
	if len(c.Queue().Pending()) != 1 {
		t.Fatalf("outbox pending = %d, want 1", len(c.Queue().Pending()))
	}
	// Reopen the queue from disk to prove durability.
	q2, err := edge.OpenQueue(filepath.Join(dir, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	if len(q2.Pending()) != 1 {
		t.Fatal("outbox did not survive reopen")
	}
	// Acknowledge and confirm the outbox drains.
	if err := c.AckBatch(b.Seal.Seq); err != nil {
		t.Fatal(err)
	}
	if len(c.Queue().Pending()) != 0 {
		t.Fatal("outbox did not drain after ack")
	}
}

// Deleting the local log must not restart cleanly. Boot must return ErrRollback
// and mark the controller degraded.
func TestRollbackOnBootDetected(t *testing.T) {
	dir := t.TempDir()
	ks, priv := keys(t)
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	store := ledger.NewMemStore()

	c, err := openController(t, dir, ks, priv, store, clk)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		c.Record(ledger.KindWeigh, map[string]any{"n": i})
	}
	if err := c.Checkpoint(); err != nil {
		t.Fatal(err)
	}

	// Attacker wipes the log but leaves the state file (or the state file was on
	// a different partition). Either way the log is now short of the seal.
	store.Mutate(func(recs []ledger.Record) []ledger.Record { return nil })

	c2, err := openController(t, dir, ks, priv, store, clk)
	if !errors.Is(err, edge.ErrRollback) {
		t.Fatalf("want ErrRollback, got %v", err)
	}
	if c2 == nil || !c2.Degraded {
		t.Fatal("controller should be degraded after rollback detection")
	}
}

// Truncating to a still-valid prefix is the subtle case: the remaining chain
// verifies, but it is shorter than the seal.
func TestTruncationOnBootDetected(t *testing.T) {
	dir := t.TempDir()
	ks, priv := keys(t)
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	store := ledger.NewMemStore()
	c, err := openController(t, dir, ks, priv, store, clk)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		c.Record(ledger.KindWeigh, map[string]any{"n": i})
	}
	c.Checkpoint()
	store.Mutate(func(recs []ledger.Record) []ledger.Record { return recs[:4] })

	_, err = openController(t, dir, ks, priv, store, clk)
	if !errors.Is(err, edge.ErrRollback) {
		t.Fatalf("want ErrRollback on truncated prefix, got %v", err)
	}
}

// An uninterrupted restart is clean: no rollback, not degraded.
func TestCleanRestart(t *testing.T) {
	dir := t.TempDir()
	ks, priv := keys(t)
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	store := ledger.NewMemStore()
	c, err := openController(t, dir, ks, priv, store, clk)
	if err != nil {
		t.Fatal(err)
	}
	c.Record(ledger.KindWeigh, map[string]any{"n": 1})
	c.Checkpoint()
	c2, err := openController(t, dir, ks, priv, store, clk)
	if err != nil {
		t.Fatalf("clean restart failed: %v", err)
	}
	if c2.Degraded {
		t.Fatal("clean restart wrongly flagged degraded")
	}
	if c2.Ledger().Len() != c.Ledger().Len()+1 { // +1 boot event
		t.Fatalf("unexpected len after restart: %d vs %d", c2.Ledger().Len(), c.Ledger().Len())
	}
}
