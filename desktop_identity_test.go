package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var identityTestOwner = captureOwner{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}

// Synthetic test pins only; this file is never part of a deployed binary.
func init() {
	identityLabNode = "44444444-4444-4444-8444-444444444444"
	identityLabSID = "S-1-5-21-1000000001-1000000002-1000000003-1001"
	identityLabNodeURI = "spiffe://example.test/test/node/" + identityLabNode
}

func TestDesktopIdentityBuildPinsFailClosed(t *testing.T) {
	if identityBuildPinsValid("", "", "") || identityBuildPinsValid(identityLabNode, identityLabSID, "") || identityBuildPinsValid(identityLabNode, "", identityLabNodeURI) {
		t.Fatal("missing deployment pins accepted")
	}
	if !identityBuildPinsValid(identityLabNode, identityLabSID, identityLabNodeURI) {
		t.Fatal("complete synthetic pins rejected")
	}
	for _, sid := range []string{"", "S-1-5-18", "S-1-5-21-1", "S-1-5-21-1-2-3-4294967296"} {
		if _, err := identitySIDParts(sid); err == nil {
			t.Fatal("invalid local SID accepted")
		}
	}
}

func identityTestMapping() desktopIdentityMapping {
	return desktopIdentityMapping{identityLabNode, identityTestOwner.TID, identityTestOwner.OID, identityTestOwner.AppID, identityLabSID}
}
func identityTestStatus(rows ...map[string]any) map[string]any {
	list := []any{}
	for _, r := range rows {
		list = append(list, r)
	}
	return map[string]any{"ok": true, "paused": false, "sessions": list, "identity_login": map[string]any{"ready": true, "sid": identityLabSID}}
}

func TestDesktopIdentitySessionDecisions(t *testing.T) {
	for _, tc := range []struct {
		name          string
		row           map[string]any
		code          string
		create, reuse bool
	}{
		{"empty", nil, "", true, false},
		{"same user", map[string]any{"sid": identityLabSID, "session_id": float64(1), "state": "active", "locked": false}, "", false, true},
		{"locked", map[string]any{"sid": identityLabSID, "state": "active", "locked": true}, "identity_unlock_unsupported", false, false},
		{"disconnected", map[string]any{"sid": identityLabSID, "state": "disconnected", "locked": false}, "session_disconnected", false, false},
		{"someone else", map[string]any{"sid": "S-1-5-21-1", "state": "active", "locked": false}, "session_conflict", false, false},
		{"unknown SID", map[string]any{"user": "test-user", "state": "active", "locked": false}, "session_state_unknown", false, false},
		{"unknown lock", map[string]any{"sid": identityLabSID, "state": "active"}, "session_not_ready", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := identityTestStatus()
			if tc.row != nil {
				st = identityTestStatus(tc.row)
			}
			out, create := desktopLoginDecision(st, identityLabSID)
			if create != tc.create || (!create && asStr(out["error_code"]) != tc.code) || (tc.reuse && out["reused"] != true) {
				t.Fatalf("%v create=%v", out, create)
			}
		})
	}
	st := identityTestStatus()
	st["paused"] = true
	if out, create := desktopLoginDecision(st, identityLabSID); create || out["error_code"] != "desktop_paused" {
		t.Fatal(out)
	}
	st = identityTestStatus(map[string]any{"sid": identityLabSID}, map[string]any{"sid": identityLabSID})
	if out, create := desktopLoginDecision(st, identityLabSID); create || out["error_code"] != "session_ambiguous" {
		t.Fatal(out)
	}
	st = identityTestStatus()
	st["identity_login"] = map[string]any{"ready": false}
	if out, create := desktopLoginDecision(st, identityLabSID); create || out["error_code"] != "identity_backend_unavailable" {
		t.Fatal(out)
	}
}

func TestDesktopIdentityGrantABI(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ft := now.UnixNano()/100 + 116444736000000000
	c := map[string]any{"boot": strings.Repeat("ab", 32), "session": float64(7), "now": float64(ft)}
	g, err := signDesktopIdentity(key, identityTestMapping(), c, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 420 || binary.LittleEndian.Uint32(g[:4]) != 0x31414c52 || binary.LittleEndian.Uint32(g[4:8]) != 420 || binary.LittleEndian.Uint32(g[8:12]) != 7 || binary.LittleEndian.Uint32(g[12:16]) != 0 || binary.LittleEndian.Uint64(g[16:24]) != uint64(ft+450000000) {
		t.Fatal("wire header/expiry mismatch")
	}
	if hex.EncodeToString(g[24:56]) != c["boot"] || hex.EncodeToString(g[88:104]) != strings.ReplaceAll(identityTestOwner.TID, "-", "") {
		t.Fatal("grant binding mismatch")
	}
	// SID bytes from the Windows SID ABI, independent of the grant builder.
	want := []uint32{21, 1000000001, 1000000002, 1000000003, 1001}
	if hex.EncodeToString(g[136:144]) != "0105000000000005" {
		t.Fatal("SID header")
	}
	for i, n := range want {
		if binary.LittleEndian.Uint32(g[144+i*4:]) != n {
			t.Fatal("SID subauthority")
		}
	}
	h := sha256.Sum256(g[:164])
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], g[164:]) != nil {
		t.Fatal("signature mismatch")
	}
	g[120] ^= 1
	h = sha256.Sum256(g[:164])
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], g[164:]) == nil {
		t.Fatal("changed node accepted")
	}
	c["now"] = float64(ft - 600000000)
	if _, e := signDesktopIdentity(key, identityTestMapping(), c, now); e == nil {
		t.Fatal("clock skew accepted")
	}
}

func identityTestService(t *testing.T) (*DesktopService, *rsa.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	keyPath := filepath.Join(dir, "signer.pem")
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); e != nil {
		t.Fatal(e)
	}
	cfg := desktopIdentitySettings{KeyFile: keyPath, Mappings: []desktopIdentityMapping{identityTestMapping()}}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "identity.json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	return &DesktopService{identityConfig: path}, key
}

func TestDesktopIdentityMappingAndNoSideEffects(t *testing.T) {
	s, _ := identityTestService(t)
	m, path, e := s.identityMapping(identityTestOwner, identityLabNode)
	if e != nil || m.SID != identityLabSID {
		t.Fatal(e)
	}
	for _, owner := range []captureOwner{{"wrong", identityTestOwner.OID, identityTestOwner.AppID}, {identityTestOwner.TID, "wrong", identityTestOwner.AppID}, {identityTestOwner.TID, identityTestOwner.OID, "wrong"}} {
		if _, _, e := s.identityMapping(owner, identityLabNode); e == nil {
			t.Fatal("identity substitution accepted")
		}
	}
	if _, _, e := s.identityMapping(identityTestOwner, "other-node"); e == nil {
		t.Fatal("wrong node accepted")
	}
	if _, _, e := s.identityMapping(identityTestOwner, identityLabNodeURI); e != nil {
		t.Fatal("pinned full node URI rejected", e)
	}
	if _, _, e := s.identityMapping(identityTestOwner, "spiffe://other.test/test/node/"+identityLabNode); e == nil {
		t.Fatal("wrong trust domain accepted")
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = desktopIdentityKey(path); e == nil {
		t.Fatal("publicly readable key accepted")
	}
	calls := 0
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		calls++
		if r["op"] != "status" {
			t.Fatal("locked user triggered login")
		}
		return identityTestStatus(map[string]any{"sid": identityLabSID, "locked": true, "state": "active"}), nil
	}
	out, code := s.loginDesktop(context.Background(), identityTestOwner, identityLabNode, "test", func(string, map[string]any, map[string]any) {})
	if calls != 1 || code != 409 || out["error_code"] != "identity_unlock_unsupported" {
		t.Fatalf("%v %d %d", out, code, calls)
	}
}

func TestDesktopIdentityLoginKeepsGrantOutOfAudit(t *testing.T) {
	s, key := identityTestService(t)
	var operations []string
	var audits []map[string]any
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		op := asStr(r["op"])
		operations = append(operations, op)
		switch op {
		case "status":
			return identityTestStatus(), nil
		case "identity_challenge":
			return map[string]any{"ok": true, "challenge": map[string]any{"boot": strings.Repeat("cd", 32), "session": float64(1), "now": float64(time.Now().UnixNano()/100 + 116444736000000000)}}, nil
		case "identity_login":
			g := r["identity_grant"].([]byte)
			h := sha256.Sum256(g[:164])
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], g[164:]) != nil {
				t.Fatal("bad signature")
			}
			return map[string]any{"ok": true, "sid": identityLabSID, "session_id": float64(1)}, nil
		}
		t.Fatalf("unexpected op %s", op)
		return nil, nil
	}
	ctx := context.WithValue(context.Background(), desktopAuthorizeKey{}, func() error { return nil })
	out, code := s.loginDesktop(ctx, identityTestOwner, identityLabNode, "test", func(_ string, d, r map[string]any) { audits = append(audits, d, r) })
	if code != 200 || out["ok"] != true || strings.Join(operations, ",") != "status,identity_challenge,identity_login" {
		t.Fatalf("%v %d %v", out, code, operations)
	}
	b, _ := json.Marshal(audits)
	if strings.Contains(string(b), "identity_grant") || strings.Contains(string(b), "challenge") || strings.Contains(string(b), strings.Repeat("cd", 32)) {
		t.Fatal("authentication material in audit")
	}
}

func TestDesktopStatusDuringHeldInteraction(t *testing.T) {
	s := &DesktopService{busy: map[string]bool{"node": true}}
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		if r["op"] != "status" {
			t.Fatal(r)
		}
		return identityTestStatus(), nil
	}
	out, code := s.execute(context.Background(), identityTestOwner, "node", "status", desktopRequest{Node: "node"}, "test", func(string, map[string]any, map[string]any) {})
	if code != 200 || out["ok"] != true || !s.busy["node"] {
		t.Fatal(out, code)
	}
}
