package ledger_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"hazmatcontrol/internal/clock"
	"hazmatcontrol/internal/ledger"
)

func newLog(t *testing.T) (*ledger.Log, *ledger.MemStore, ledger.Keyring, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := ledger.Keyring{"k1": pub}
	store := ledger.NewMemStore()
	clk := clock.NewFake(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	l, err := ledger.Open("dev-1", "k1", priv, keys, store, clk)
	if err != nil {
		t.Fatal(err)
	}
	return l, store, keys, priv
}

func appendN(t *testing.T, l *ledger.Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.Append(ledger.KindWeigh, map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifies(t *testing.T) {
	l, _, keys, _ := newLog(t)
	appendN(t, l, 5)
	if err := ledger.VerifyChain(l.Records(), keys); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

// Editing a payload must be detected: the hash no longer matches.
func TestPayloadEditDetected(t *testing.T) {
	l, store, keys, _ := newLog(t)
	appendN(t, l, 5)
	store.Mutate(func(recs []ledger.Record) []ledger.Record {
		recs[2].Payload = []byte(`{"grams":999999}`)
		return recs
	})
	recs, _ := store.Load()
	if err := ledger.VerifyChain(recs, keys); err == nil {
		t.Fatal("edited payload was not detected")
	}
}

// Deleting a middle record must be detected as a sequence gap.
func TestDeletionDetected(t *testing.T) {
	l, store, keys, _ := newLog(t)
	appendN(t, l, 5)
	store.Mutate(func(recs []ledger.Record) []ledger.Record {
		return append(recs[:2], recs[3:]...)
	})
	recs, _ := store.Load()
	if err := ledger.VerifyChain(recs, keys); !errors.Is(err, ledger.ErrChainBroken) {
		t.Fatalf("want chain-broken on deletion, got %v", err)
	}
}

// Reordering records must be detected.
func TestReorderDetected(t *testing.T) {
	l, store, keys, _ := newLog(t)
	appendN(t, l, 5)
	store.Mutate(func(recs []ledger.Record) []ledger.Record {
		recs[1], recs[3] = recs[3], recs[1]
		return recs
	})
	recs, _ := store.Load()
	if err := ledger.VerifyChain(recs, keys); err == nil {
		t.Fatal("reorder was not detected")
	}
}

// Forging a record without the private key must fail signature verification,
// even if the attacker recomputes a consistent hash chain.
func TestForgeryWithoutKeyRejected(t *testing.T) {
	l, store, keys, _ := newLog(t)
	appendN(t, l, 3)
	// Attacker removes the last record and appends a fake one, recomputing the
	// hash correctly but signing with their own key.
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	store.Mutate(func(recs []ledger.Record) []ledger.Record {
		recs = recs[:3]
		fake := ledger.Record{
			Version: ledger.FormatVersion, DeviceID: "dev-1", Seq: 3,
			At: time.Now(), Kind: ledger.KindWeigh, Payload: []byte(`{"n":"erased"}`),
			PrevHash: recs[2].Hash, KeyID: "k1",
		}
		ledger.Sign(&fake, "k1", attackerPriv)
		return append(recs, fake)
	})
	recs, _ := store.Load()
	if err := ledger.VerifyChain(recs, keys); !errors.Is(err, ledger.ErrSignature) {
		t.Fatalf("forged record not caught by signature check: %v", err)
	}
}

// A seal pins the head; truncating the tail afterwards is detectable.
func TestTruncationDetectedBySeal(t *testing.T) {
	l, store, keys, priv := newLog(t)
	appendN(t, l, 5)
	seal := l.Seal()
	if err := ledger.VerifySeal(seal, keys); err != nil {
		t.Fatalf("valid seal rejected: %v", err)
	}
	// Attacker truncates to 3 records and restarts a fresh log over the truncated
	// store, then appends new events. The chain alone still verifies (it is a
	// self-consistent shorter chain), which is exactly why the seal exists.
	store.Mutate(func(recs []ledger.Record) []ledger.Record { return recs[:3] })
	recs, _ := store.Load()
	if err := ledger.VerifyChain(recs, keys); err != nil {
		t.Fatalf("truncated chain is internally valid by design: %v", err)
	}
	if err := ledger.CheckAgainstSeal(recs, seal); err == nil {
		t.Fatal("seal failed to detect truncation")
	}
	_ = priv
}

// Re-sealing the truncated log with the real key is also caught, because the
// hash at the sealed seq differs from the original head hash. (This models a
// restored backup that a later boot re-sealed.)
func TestSealDetectsDivergentHistory(t *testing.T) {
	l, store, keys, priv := newLog(t)
	appendN(t, l, 5)
	seal := l.Seal()

	// Rewrite record 4's payload and re-sign the whole tail with the real key,
	// simulating a compromised-but-keyed device.
	_, _ = store.Load()
	keys2 := keys
	l2, err := ledger.Open("dev-1", "k1", priv, keys2, store, clock.NewFake(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	_ = l2
	// Simpler: build a second, independent log with the same key and a different
	// history at the same seqs.
	store2 := ledger.NewMemStore()
	l3, err := ledger.Open("dev-1", "k1", priv, keys2, store2, clock.NewFake(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		l3.Append(ledger.KindWeigh, map[string]any{"n": i, "tamper": true})
	}
	recs2, _ := store2.Load()
	if err := ledger.CheckAgainstSeal(recs2, seal); err == nil {
		t.Fatal("divergent history with a valid signature was not caught by the seal")
	}
}

// A seal signed by the wrong key must not verify.
func TestSealSignatureChecked(t *testing.T) {
	l, _, _, _ := newLog(t)
	appendN(t, l, 2)
	seal := l.Seal()
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := ledger.VerifySeal(seal, ledger.Keyring{"k1": otherPub}); err == nil {
		t.Fatal("seal accepted under the wrong key")
	}
}
