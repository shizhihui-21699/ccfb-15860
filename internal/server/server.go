// Package server exposes the controller over HTTP for two audiences:
//
//   - the cabinet's local operator console (touchscreen next to the cabinet),
//     which drives authentication, unlocking, removal and weighing;
//   - HQ sync, which pushes batches and pulls acknowledgements.
//
// All endpoints are thin: they translate JSON to calls on the session/edge
// layers and never contain policy. That keeps the security rules in one place
// and testable without HTTP.
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/biometric"
	"hazmatcontrol/internal/edge"
	"hazmatcontrol/internal/hq"
	"hazmatcontrol/internal/ledger"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/session"
)

// Server is the HTTP façade. A single controller runs one active session at a
// time (there is one cabinet), so the session is held behind a mutex.
type Server struct {
	mu      sync.Mutex
	ctrl    *edge.Controller
	ingest  *hq.Ingest // nil on a device; set on the HQ instance
	factory SessionFactory
	cur     *session.Session
}

// SessionFactory builds a session for a cabinet. It is injected so the server
// does not need to know how the stack is wired.
type SessionFactory func(id string, p model.Product, authGrams float64, a, b model.OperatorID) (*session.Session, error)

func New(ctrl *edge.Controller, factory SessionFactory) *Server {
	return &Server{ctrl: ctrl, factory: factory}
}

// WithIngest turns this server into an HQ endpoint that accepts batches.
func (s *Server) WithIngest(in *hq.Ingest) *Server {
	s.ingest = in
	return s
}

// Handler returns the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", s.openSession)
	mux.HandleFunc("POST /v1/sessions/{id}/auth", s.auth)
	mux.HandleFunc("POST /v1/sessions/{id}/arm", s.arm)
	mux.HandleFunc("POST /v1/sessions/{id}/unlock", s.unlock)
	mux.HandleFunc("POST /v1/sessions/{id}/remove", s.remove)
	mux.HandleFunc("POST /v1/sessions/{id}/reconcile", s.reconcile)
	mux.HandleFunc("POST /v1/sessions/{id}/close", s.close)
	mux.HandleFunc("GET /v1/sessions/{id}", s.status)
	mux.HandleFunc("GET /v1/presence", s.presence)
	mux.HandleFunc("POST /v1/sync/push", s.syncPush)    // device -> HQ
	mux.HandleFunc("GET /v1/sync/status", s.syncStatus) // device/operator view
	return mux
}

func (s *Server) session(id string) (*session.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil || s.cur.ID != id {
		return nil, errNotFound
	}
	return s.cur, nil
}

var errNotFound = errors.New("no such session")

type openReq struct {
	ID          string  `json:"id"`
	SKU         string  `json:"sku"`
	Name        string  `json:"name"`
	CAS         string  `json:"cas"`
	Hazard      string  `json:"hazard"`
	AuthorisedG float64 `json:"authorised_g"`
	OperatorA   string  `json:"operator_a"`
	OperatorB   string  `json:"operator_b"`
}

func (s *Server) openSession(w http.ResponseWriter, r *http.Request) {
	var req openReq
	if !decode(w, r, &req) {
		return
	}
	if id, _ := s.ctrlActive(); id != "" {
		writeErr(w, http.StatusConflict, "a session is already active", nil)
		return
	}
	p := model.Product{SKU: req.SKU, Name: req.Name, CAS: req.CAS, Hazard: model.HazardClass(req.Hazard)}
	sess, err := s.factory(req.ID, p, req.AuthorisedG, model.OperatorID(req.OperatorA), model.OperatorID(req.OperatorB))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	s.mu.Lock()
	s.cur = sess
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"id": sess.ID, "state": sess.State()})
}

func (s *Server) ctrlActive() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return "", false
	}
	return s.cur.ID, true
}

type authReq struct {
	Operator string `json:"operator"`
	Samples  []struct {
		Modality string  `json:"modality"`
		Quality  float64 `json:"quality"`
		Score    float64 `json:"score"`
		Liveness float64 `json:"liveness"`
		Reason   string  `json:"reason"`
	} `json:"samples"`
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	var req authReq
	if !decode(w, r, &req) {
		return
	}
	sess, err := s.session(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error(), nil)
		return
	}
	samples := make([]biometric.Sample, len(req.Samples))
	for i, in := range req.Samples {
		samples[i] = biometric.Sample{
			Modality: biometric.Modality(in.Modality), Quality: in.Quality, Score: in.Score,
			Liveness: in.Liveness, Reason: biometric.Reason(in.Reason),
			Operator: model.OperatorID(req.Operator), At: time.Now(),
		}
	}
	d, err := sess.Authenticate(model.OperatorID(req.Operator), samples)
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error(), map[string]any{"decision": d})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": d.Mode, "confidence": d.Confidence, "detail": d.Detail})
}

func (s *Server) arm(w http.ResponseWriter, r *http.Request) {
	sess, err := s.session(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error(), nil)
		return
	}
	if err := sess.ArmBoth(); err != nil {
		writeErr(w, http.StatusForbidden, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": sess.State()})
}

type unlockReq struct {
	Slot     string `json:"slot"`
	Operator string `json:"operator"`
	FobID    string `json:"fob_id"`
	Proof    string `json:"distinctness_proof"`
}

func (s *Server) unlock(w http.ResponseWriter, r *http.Request) {
	var req unlockReq
	if !decode(w, r, &req) {
		return
	}
	sess, err := s.session(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error(), nil)
		return
	}
	err = sess.Present(access.Slot(req.Slot), access.Credential{
		Operator: model.OperatorID(req.Operator), FobID: req.FobID, DistinctnessProof: req.Proof,
	})
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": sess.State()})
}

type removeReq struct {
	Container string  `json:"container"`
	ClaimedG  float64 `json:"claimed_g"`
	Operator  string  `json:"operator"`
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	var req removeReq
	if !decode(w, r, &req) {
		return
	}
	sess, err := s.session(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error(), nil)
		return
	}
	res, err := sess.RecordRemoval(req.Container, req.ClaimedG, model.OperatorID(req.Operator))
	body := map[string]any{"verdict": res.Verdict, "removed_g": res.RemovedGrams, "detail": res.Detail}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error(), body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	sess, err := s.session(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error(), nil)
		return
	}
	if err := sess.BeginReconcile(); err != nil {
		writeErr(w, http.StatusConflict, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": sess.State()})
}

func (s *Server) close(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Operator string `json:"operator"`
	}
	if !decode(w, r, &req) {
		return
	}
	sess, err := s.session(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error(), nil)
		return
	}
	if err := sess.Close(model.OperatorID(req.Operator)); err != nil {
		writeErr(w, http.StatusConflict, err.Error(), nil)
		return
	}
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
	// Seal the session end into the durable state so truncation stays detectable.
	_ = s.ctrl.Checkpoint()
	writeJSON(w, http.StatusOK, map[string]any{"state": sess.State()})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	sess, err := s.session(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error(), nil)
		return
	}
	s.mu.Lock()
	t := sess.Totals()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"id": sess.ID, "state": sess.State(), "reason": sess.CloseReason(),
		"claimed_g": t.ClaimedGrams, "removed_g": t.RemovedGrams,
		"removals": t.Removals, "discrepancies": t.Discrepancies,
	})
}

func (s *Server) presence(w http.ResponseWriter, r *http.Request) {
	// Presence is exposed via the edge ledger's boot state; a richer endpoint
	// would query the tracker directly. Here we report device liveness.
	writeJSON(w, http.StatusOK, map[string]any{
		"online": s.ctrl.Online(), "degraded": s.ctrl.Degraded,
		"clock_skew_ms": s.ctrl.ClockSkew().Milliseconds(),
	})
}

type pushReq struct {
	Batch json.RawMessage `json:"batch"`
}

func (s *Server) syncPush(w http.ResponseWriter, r *http.Request) {
	if s.ingest == nil {
		writeErr(w, http.StatusNotImplemented, "not an HQ endpoint", nil)
		return
	}
	var req pushReq
	if !decode(w, r, &req) {
		return
	}
	var batch ledger.Batch
	if err := json.Unmarshal(req.Batch, &batch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := s.ingest.Accept(batch); err != nil {
		writeErr(w, http.StatusConflict, err.Error(), map[string]any{"device": batch.DeviceID})
		return
	}
	st, _ := s.ingest.Status(batch.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "head_seq": st.HeadSeq, "accepted_seq": batch.Seal.Seq})
}

func (s *Server) syncStatus(w http.ResponseWriter, r *http.Request) {
	b, err := s.ctrl.EnqueueBatch()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pending_records": len(b.Records), "seal_seq": b.Seal.Seq,
		"online": s.ctrl.Online(), "degraded": s.ctrl.Degraded,
	})
}

// ---- helpers ---------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error(), nil)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string, extra map[string]any) {
	body := map[string]any{"error": msg}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, code, body)
}
