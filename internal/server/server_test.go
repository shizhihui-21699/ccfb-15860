package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hazmatcontrol/internal/hq"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/server"
	"hazmatcontrol/internal/session"
	"hazmatcontrol/internal/sim"
)

// newTestServer builds a full simulated stack behind an httptest server.
func newTestServer(t *testing.T) (*httptest.Server, *sim.Stack) {
	t.Helper()
	st, err := sim.New(t.TempDir(), time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	factory := func(id string, p model.Product, authGrams float64, a, b model.OperatorID) (*session.Session, error) {
		return st.NewSession(id, p, authGrams, a, b)
	}
	srv := server.New(st.Edge, factory).WithIngest(hq.NewIngest(st.Keys))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func post(t *testing.T, ts *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestHTTPSessionFlow(t *testing.T) {
	ts, st := newTestServer(t)
	if err := st.EnrolOperator("alice", "fa"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnrolOperator("bob", "fb"); err != nil {
		t.Fatal(err)
	}

	code, body := post(t, ts, "/v1/sessions", map[string]any{
		"id": "S1", "sku": "KCN", "name": "氰化钾", "hazard": "highly_toxic",
		"authorised_g": 50, "operator_a": "alice", "operator_b": "bob",
	})
	if code != http.StatusCreated {
		t.Fatalf("open: %d %v", code, body)
	}

	face := map[string]any{"modality": "face", "quality": 0.9, "score": 0.93, "liveness": 0.95, "reason": "ok"}
	code, body = post(t, ts, "/v1/sessions/S1/auth", map[string]any{"operator": "alice", "samples": []any{face}})
	if code != http.StatusOK {
		t.Fatalf("alice auth: %d %v", code, body)
	}
	code, body = post(t, ts, "/v1/sessions/S1/auth", map[string]any{"operator": "bob", "samples": []any{face}})
	if code != http.StatusOK {
		t.Fatalf("bob auth: %d %v", code, body)
	}

	// Presence: both fobs live.
	st.Beep("fa", -52)
	st.Beep("fb", -54)
	code, body = post(t, ts, "/v1/sessions/S1/arm", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("arm: %d %v", code, body)
	}

	code, body = post(t, ts, "/v1/sessions/S1/unlock", map[string]any{"slot": "A", "operator": "alice", "fob_id": "fa"})
	if code != http.StatusOK {
		t.Fatalf("unlock A: %d %v", code, body)
	}
	code, body = post(t, ts, "/v1/sessions/S1/unlock", map[string]any{"slot": "B", "operator": "bob", "fob_id": "fb"})
	if code != http.StatusOK {
		t.Fatalf("unlock B: %d %v", code, body)
	}

	st.Scale.SetTare("drum", 500, st.Clk.Now())
	st.Scale.PlaceBefore("drum", 12000, st.Clk.Now(), 5)
	st.Scale.PlaceAfter("drum", 11980, st.Clk.Now(), 5)
	code, body = post(t, ts, "/v1/sessions/S1/remove", map[string]any{"container": "drum", "claimed_g": 20, "operator": "alice"})
	if code != http.StatusOK {
		t.Fatalf("remove: %d %v", code, body)
	}
	if body["verdict"] != "matched" {
		t.Fatalf("verdict = %v", body["verdict"])
	}

	code, body = post(t, ts, "/v1/sessions/S1/reconcile", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("reconcile: %d %v", code, body)
	}
	code, body = post(t, ts, "/v1/sessions/S1/close", map[string]any{"operator": "alice"})
	if code != http.StatusOK {
		t.Fatalf("close: %d %v", code, body)
	}

	// Sync the whole backlog to HQ via the HTTP endpoint.
	code, body = post(t, ts, "/v1/sessions", map[string]any{}) // second open must not conflict now
	if code == http.StatusConflict {
		t.Fatal("session slot not freed after close")
	}
}

func TestHTTPOverageReturnsConflict(t *testing.T) {
	ts, st := newTestServer(t)
	st.EnrolOperator("alice", "fa")
	st.EnrolOperator("bob", "fb")
	post(t, ts, "/v1/sessions", map[string]any{
		"id": "S2", "sku": "KCN", "name": "氰化钾", "hazard": "highly_toxic",
		"authorised_g": 30, "operator_a": "alice", "operator_b": "bob",
	})
	face := map[string]any{"modality": "face", "quality": 0.9, "score": 0.93, "liveness": 0.95, "reason": "ok"}
	post(t, ts, "/v1/sessions/S2/auth", map[string]any{"operator": "alice", "samples": []any{face}})
	post(t, ts, "/v1/sessions/S2/auth", map[string]any{"operator": "bob", "samples": []any{face}})
	st.Beep("fa", -52)
	st.Beep("fb", -54)
	post(t, ts, "/v1/sessions/S2/arm", map[string]any{})
	post(t, ts, "/v1/sessions/S2/unlock", map[string]any{"slot": "A", "operator": "alice", "fob_id": "fa"})
	post(t, ts, "/v1/sessions/S2/unlock", map[string]any{"slot": "B", "operator": "bob", "fob_id": "fb"})

	st.Scale.SetTare("drum", 500, st.Clk.Now())
	st.Scale.PlaceBefore("drum", 12000, st.Clk.Now(), 5)
	st.Scale.PlaceAfter("drum", 11940, st.Clk.Now(), 5) // 60g removed, 30g authorised
	code, body := post(t, ts, "/v1/sessions/S2/remove", map[string]any{"container": "drum", "claimed_g": 30, "operator": "alice"})
	if code != http.StatusConflict {
		t.Fatalf("overage should be 409, got %d %v", code, body)
	}
}
