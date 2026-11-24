// Command demo walks through the controlled-withdrawal flow end to end using the
// simulated hardware stack, so the policy can be seen without physical devices.
//
// It runs four scenarios:
//
//  1. a clean two-person withdrawal that reconciles against the scale;
//  2. a masked operator verified through the fallback path;
//  3. the "one person, two badges" attempt being refused;
//  4. the "two people, then one leaves" attempt being aborted and relocked.
//
// Every step is written to the tamper-evident ledger, whose chain is verified at
// the end, and the backlog is synced to an in-process HQ.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"hazmatcontrol/internal/access"
	"hazmatcontrol/internal/biometric"
	"hazmatcontrol/internal/hq"
	"hazmatcontrol/internal/ledger"
	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/session"
	"hazmatcontrol/internal/sim"
)

const (
	alice = model.OperatorID("张伟")
	bob   = model.OperatorID("李强")
	fobA  = "fob-zhangwei"
	fobB  = "fob-liqiang"
)

func main() {
	dir, err := os.MkdirTemp("", "hazmat-demo-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	st, err := sim.New(dir, time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	if err := st.EnrolOperator(alice, fobA); err != nil {
		panic(err)
	}
	if err := st.EnrolOperator(bob, fobB); err != nil {
		panic(err)
	}

	product := model.Product{SKU: "KCN-001", Name: "氰化钾", CAS: "151-50-8", Hazard: model.HazardHighlyToxic, Unit: "g"}

	section("场景 1：双人同时在场，正常领用并称重对账")
	happyPath(st, product)

	section("场景 2：戴防护面罩，人脸不可用，走替代核验")
	maskedPath(st, product)

	section("场景 3：一人拿同事工卡，试图独自完成双人验证")
	badgeSharing(st, product)

	section("场景 4：两人一起核验后，一人离开，另一人继续取货")
	collusion(st, product)

	section("审计：校验哈希链并同步到总部")
	audit(st)
}

func happyPath(st *sim.Stack, p model.Product) {
	lapsePresence(st)
	s := mustSession(st, "S-1001", p, 50)
	authBoth(st, s, false)
	beepBoth(st)
	must("arm", s.ArmBoth())
	unlockBoth(st, s, "")
	st.Scale.SetTare("drum-KCN-1", 500, st.Clk.Now())
	st.Scale.PlaceBefore("drum-KCN-1", 12000, st.Clk.Now(), 5)
	st.Scale.PlaceAfter("drum-KCN-1", 11980, st.Clk.Now(), 5)
	res, err := s.RecordRemoval("drum-KCN-1", 20, alice)
	report("取货 20g", err)
	fmt.Printf("    称重结果: %s  %s\n", res.Verdict, res.Detail)
	must("begin reconcile", s.BeginReconcile())
	must("close", s.Close(alice))
	fmt.Printf("    会话状态: %s  门锁已闭合: %v\n", s.State(), !st.Act.AnyOpen())
}

func maskedPath(st *sim.Stack, p model.Product) {
	lapsePresence(st)
	s := mustSession(st, "S-1002", p, 30)
	_, err := s.Authenticate(alice, facePass(st))
	must("alice face", err)
	// Bob's face is hidden by a respirator; a voice sample verifies him.
	at := st.Clk.Now()
	samples := []biometric.Sample{
		{Modality: biometric.ModFace, Quality: 0.2, Reason: biometric.ReasonMasked, At: at},
		{Modality: biometric.ModVoice, Quality: 0.8, Score: 0.86, Liveness: 0.9, Reason: biometric.ReasonOK, At: at},
	}
	d, err := s.Authenticate(bob, samples)
	must("bob fallback", err)
	fmt.Printf("    李强 核验方式: %s  置信度 %.2f  (%s)\n", d.Mode, d.Confidence, d.Detail)
	fmt.Printf("    审计记录已注明面部被遮挡: %v\n", ledgerContains(st, "face_covered"))
}

func badgeSharing(st *sim.Stack, p model.Product) {
	lapsePresence(st)
	s := mustSession(st, "S-1003", p, 50)
	_, err := s.Authenticate(alice, facePass(st))
	must("alice face", err)
	// Someone presents Bob's identity but Alice's face/voice.
	wrongFace := []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.9, Score: 0.2, Liveness: 0.95,
		Reason: biometric.ReasonLowScore, At: st.Clk.Now(),
	}}
	_, err = s.Authenticate(bob, wrongFace)
	report("用张伟的脸冒充李强", err)
	// Even if identity were spoofed, presence needs Bob's fob on a second body.
	_, err = s.Authenticate(bob, facePass(st))
	must("(simulated) bob auth", err)
	beepOnly(st, fobA) // only Alice's fob is here
	err = s.ArmBoth()
	report("只有一具身体在场时尝试武装双锁", err)
	fmt.Printf("    门锁是否被打开: %v\n", st.Act.AnyOpen())
}

func collusion(st *sim.Stack, p model.Product) {
	lapsePresence(st)
	s := mustSession(st, "S-1004", p, 100)
	authBoth(st, s, false)
	beepBoth(st)
	must("arm", s.ArmBoth())
	unlockBoth(st, s, "")
	st.Scale.SetTare("drum-KCN-2", 500, st.Clk.Now())
	st.Scale.PlaceBefore("drum-KCN-2", 12000, st.Clk.Now(), 5)
	st.Scale.PlaceAfter("drum-KCN-2", 11990, st.Clk.Now(), 5)
	_, err := s.RecordRemoval("drum-KCN-2", 10, alice)
	must("first removal (both present)", err)
	fmt.Println("    第一次取货成功（两人在场）")
	// Bob leaves: his fob stops emitting. Alice keeps going.
	st.Clk.Advance(40 * time.Second)
	beepOnly(st, fobA)
	st.Scale.PlaceBefore("drum-KCN-3", 20000, st.Clk.Now(), 5)
	st.Scale.PlaceAfter("drum-KCN-3", 19500, st.Clk.Now(), 5)
	_, err = s.RecordRemoval("drum-KCN-3", 500, alice)
	report("李强离开后张伟继续取货 500g", err)
	fmt.Printf("    会话状态: %s  门锁是否仍打开: %v\n", s.State(), st.Act.AnyOpen())
}

func audit(st *sim.Stack) {
	recs := st.Edge.Ledger().Records()
	err := ledger.VerifyChain(recs, st.Keys)
	report(fmt.Sprintf("校验本地哈希链（%d 条记录）", len(recs)), err)

	in := hq.NewIngest(st.Keys)
	b, err := st.Edge.EnqueueBatch()
	must("enqueue", err)
	err = in.Accept(b)
	report("总部接收并校验批次", err)
	if status, ok := in.Status("cab-1"); ok {
		fmt.Printf("    总部已持有 %d 条记录，头部 seq=%d，降级=%v\n", status.Count, status.HeadSeq, status.Degraded)
	}
}

// ---- helpers ---------------------------------------------------------------

// lapsePresence advances the clock past the lease timeout and purges all fob
// history, so each scenario starts with nobody present. The demo shares one
// stack (and therefore one tracker and clock) across scenarios.
func lapsePresence(st *sim.Stack) {
	st.Clk.Advance(60 * time.Second)
	for _, fob := range []string{fobA, fobB} {
		st.Tracker.ForciblyLapse(fob)
	}
}

func mustSession(st *sim.Stack, id string, p model.Product, auth float64) *session.Session {
	s, err := st.NewSession(id, p, auth, alice, bob)
	must("open session", err)
	return s
}

func authBoth(st *sim.Stack, s *session.Session, masked bool) {
	_, err := s.Authenticate(alice, facePass(st))
	must("alice auth", err)
	_, err = s.Authenticate(bob, facePass(st))
	must("bob auth", err)
}

func facePass(st *sim.Stack) []biometric.Sample {
	return []biometric.Sample{{
		Modality: biometric.ModFace, Quality: 0.9, Score: 0.93, Liveness: 0.95,
		Reason: biometric.ReasonOK, At: st.Clk.Now(),
	}}
}

func beepBoth(st *sim.Stack) {
	must("beep alice", st.Beep(fobA, -52))
	must("beep bob", st.Beep(fobB, -54))
}

func beepOnly(st *sim.Stack, fob string) {
	must("beep", st.Beep(fob, -52))
}

func unlockBoth(st *sim.Stack, s *session.Session, proof string) {
	must("unlock A", s.Present(access.SlotA, access.Credential{Operator: alice, FobID: fobA, DistinctnessProof: proof, At: st.Clk.Now()}))
	must("unlock B", s.Present(access.SlotB, access.Credential{Operator: bob, FobID: fobB, DistinctnessProof: proof, At: st.Clk.Now()}))
}

func ledgerContains(st *sim.Stack, s string) bool {
	for _, r := range st.Edge.Ledger().Records() {
		if len(r.Payload) > 0 && contains(string(r.Payload), s) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func section(title string) {
	fmt.Printf("\n=== %s ===\n", title)
}

func report(what string, err error) {
	switch {
	case err == nil:
		fmt.Printf("  ✓ %s：通过\n", what)
	case errors.Is(err, session.ErrPresenceLost):
		fmt.Printf("  ✗ %s：拒绝（双人同时在场不满足）\n", what)
	case errors.Is(err, session.ErrDiscrepancy):
		fmt.Printf("  ✗ %s：拒绝（称重与申报不符）\n", what)
	default:
		fmt.Printf("  ✗ %s：拒绝（%v）\n", what, err)
	}
}

func must(what string, err error) {
	if err != nil {
		fmt.Printf("  ✗ %s：致命错误 %v\n", what, err)
		os.Exit(1)
	}
}
