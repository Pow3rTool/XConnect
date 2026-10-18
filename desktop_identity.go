package main

import (
	"bytes"
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
	"errors"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Private, operator-generated build pins. Empty in ordinary public builds;
// runtime configuration alone cannot broaden the experiment to another host.
var identityLabNode, identityLabSID, identityLabNodeURI string

func identitySIDParts(sid string) ([]uint32, error) {
	parts := strings.Split(sid, "-")
	if len(parts) != 8 || strings.Join(parts[:4], "-") != "S-1-5-21" {
		return nil, errors.New("identity requires a local-account SID")
	}
	values := []uint32{21}
	for _, part := range parts[4:] {
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(v, 10) != part {
			return nil, errors.New("invalid identity SID")
		}
		values = append(values, uint32(v))
	}
	return values, nil
}

func identityBuildPinsValid(node, sid, nodeURI string) bool {
	if _, err := desktopUUID(node); err != nil {
		return false
	}
	if _, err := identitySIDParts(sid); err != nil {
		return false
	}
	u, err := url.Parse(nodeURI)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	parts := strings.Split(u.Path, "/")
	return len(parts) == 4 && parts[0] == "" && parts[1] != "" && parts[2] == "node" && parts[3] == node
}

type desktopIdentityMapping struct {
	Node      string `json:"node"`
	Tenant    string `json:"tenant"`
	Principal string `json:"principal"`
	App       string `json:"app"`
	SID       string `json:"sid"`
}
type desktopIdentitySettings struct {
	KeyFile  string                   `json:"key_file"`
	Mappings []desktopIdentityMapping `json:"mappings"`
}

// Deliberately opt-in and single-host. Live configuration is re-read for each
// request; removing a mapping/key revokes future grants without a restart.
func (s *DesktopService) identityMapping(owner captureOwner, node string) (desktopIdentityMapping, string, error) {
	var empty desktopIdentityMapping
	if !identityBuildPinsValid(identityLabNode, identityLabSID, identityLabNodeURI) {
		return empty, "", errors.New("identity login has no valid private build-time pins")
	}
	if s.identityConfig == "" {
		return empty, "", errors.New("identity login broker is not configured")
	}
	b, err := os.ReadFile(s.identityConfig)
	if err != nil {
		return empty, "", errors.New("identity login configuration unavailable")
	}
	var cfg desktopIdentitySettings
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > 16384 || d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || cfg.KeyFile == "" || len(cfg.Mappings) > 32 {
		return empty, "", errors.New("invalid identity login configuration")
	}
	var match *desktopIdentityMapping
	for _, m := range cfg.Mappings {
		if m.Node != identityLabNode || m.SID != identityLabSID {
			return empty, "", errors.New("only the single-host test identity backend is supported")
		}
		for _, v := range []string{m.Tenant, m.Principal, m.App} {
			if _, e := desktopUUID(v); e != nil {
				return empty, "", errors.New("invalid identity mapping")
			}
		}
		if node == identityLabNodeURI || node == m.Node {
			if m.Tenant == owner.TID && m.Principal == owner.OID && m.App == owner.AppID {
				if match != nil {
					return empty, "", errors.New("ambiguous identity mapping")
				}
				copy := m
				match = &copy
			}
		}
	}
	if match == nil {
		return empty, "", errors.New("caller has no identity mapping for this node")
	}
	return *match, cfg.KeyFile, nil
}

func desktopIdentityKey(path string) (*rsa.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("identity signer unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 16384 {
		return nil, errors.New("identity signing key must be a private regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, errors.New("identity signer unavailable")
	}
	defer clear(b)
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid identity signing key")
	}
	defer clear(block.Bytes)
	var key *rsa.PrivateKey
	if block.Type == "PRIVATE KEY" {
		v, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e == nil {
			key, _ = v.(*rsa.PrivateKey)
		}
	} else if block.Type == "RSA PRIVATE KEY" {
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if key == nil || key.N.BitLen() != 2048 || key.Validate() != nil {
		return nil, errors.New("identity signer requires the installed RSA-2048 lab key")
	}
	return key, nil
}

func desktopUUID(value string) ([]byte, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return nil, errors.New("invalid UUID")
	}
	b, e := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if e != nil || len(b) != 16 {
		return nil, errors.New("invalid UUID")
	}
	return b, nil
}

func signDesktopIdentity(key *rsa.PrivateKey, m desktopIdentityMapping, c map[string]any, now time.Time) ([]byte, error) {
	boot, e := hex.DecodeString(asStr(c["boot"]))
	session := number(c["session"])
	if e != nil || len(boot) != 32 || session < 1 || session >= 4294967295 || session != float64(uint32(session)) {
		return nil, errors.New("invalid identity challenge")
	}
	// A large host clock skew would otherwise turn an uncertain sign-in into
	// repeated retries. Use broker time for the grant, never a requested expiry.
	filetime := now.UnixNano()/100 + 116444736000000000
	delta := int64(number(c["now"])) - filetime
	if delta > 5*10000000 || delta < -5*10000000 {
		return nil, errors.New("identity host and broker clocks differ by more than five seconds")
	}
	g := make([]byte, 164, 420)
	binary.LittleEndian.PutUint32(g[0:4], 0x31414c52)
	binary.LittleEndian.PutUint32(g[4:8], 420)
	binary.LittleEndian.PutUint32(g[8:12], uint32(session))
	binary.LittleEndian.PutUint64(g[16:24], uint64(filetime+45*10000000))
	copy(g[24:56], boot)
	if _, e = rand.Read(g[56:88]); e != nil {
		return nil, e
	}
	for i, value := range []string{m.Tenant, m.Principal, m.Node} {
		v, e := desktopUUID(value)
		if e != nil {
			return nil, e
		}
		copy(g[88+i*16:], v)
	}
	if identityLabSID == "" || m.SID != identityLabSID {
		return nil, errors.New("unsupported identity SID")
	}
	parts, e := identitySIDParts(m.SID)
	if e != nil {
		return nil, e
	}
	g[136], g[137], g[143] = 1, 5, 5
	for i, v := range parts {
		binary.LittleEndian.PutUint32(g[144+i*4:], v)
	}
	h := sha256.Sum256(g)
	sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if e != nil {
		return nil, e
	}
	return append(g, sig...), nil
}

func sessionReceipt(code, reason string) map[string]any {
	return map[string]any{"ok": false, "error_code": code, "error": reason, "input_status": "not_sent", "next": "Inspect desktop_status; do not log off users, reset their passwords, or retry an uncertain login automatically."}
}

// Only a cryptographically authenticated caller's server-side mapping selects
// an account. Reuse is also bound to SID, including locked/disconnected sessions.
func desktopLoginDecision(status map[string]any, sid string) (map[string]any, bool) {
	if status["paused"] != false {
		return sessionReceipt("desktop_paused", "Human pause or unknown pause state blocks login"), false
	}
	rows, ok := status["sessions"].([]any)
	if !ok {
		return sessionReceipt("session_state_unknown", "Session state could not be verified"), false
	}
	var found map[string]any
	for _, v := range rows {
		r, ok := v.(map[string]any)
		if !ok || asStr(r["sid"]) == "" {
			return sessionReceipt("session_state_unknown", "A logged-on identity could not be verified"), false
		}
		if r["sid"] == sid {
			if found != nil {
				return sessionReceipt("session_ambiguous", "More than one session exists for the mapped user"), false
			}
			found = r
		}
	}
	if found != nil {
		if found["state"] == "disconnected" {
			out := sessionReceipt("session_disconnected", "The mapped user already has a disconnected session; reconnect it explicitly")
			out["session_id"] = found["session_id"]
			return out, false
		}
		if found["locked"] == true {
			out := sessionReceipt("identity_unlock_unsupported", "The existing user session is locked; identity unlock has not been implemented")
			out["session_id"] = found["session_id"]
			return out, false
		}
		if found["state"] != "active" || found["locked"] != false {
			return sessionReceipt("session_not_ready", "Existing user session is not verified active and unlocked"), false
		}
		return map[string]any{"ok": true, "reused": true, "identity_mode": "caller", "session_id": found["session_id"], "sid": sid, "user": found["user"], "console": found["console"], "next": "Observe this session before input; coordinate control with its human user."}, false
	}
	if len(rows) > 0 {
		return sessionReceipt("session_conflict", "Another user is logged on; their session will be preserved"), false
	}
	backend, _ := status["identity_login"].(map[string]any)
	if backend["ready"] != true || backend["sid"] != sid {
		return sessionReceipt("identity_backend_unavailable", "The opted-in identity backend is not ready for this mapped user"), false
	}
	return nil, true
}

func (s *DesktopService) sessionStatus(ctx context.Context, owner captureOwner, node, rid string, audit desktopAudit) (map[string]any, error) {
	out, err := s.dispatch(ctx, owner, node, map[string]any{"op": "status"}, rid, audit)
	if err != nil || out["ok"] != true {
		return out, err
	}
	m, keyPath, e := s.identityMapping(owner, node)
	identity := map[string]any{"mapped": e == nil, "signer_ready": false, "unlock": false}
	if e != nil {
		identity["reason"] = e.Error()
	} else {
		identity["sid"] = m.SID
		if _, e = desktopIdentityKey(keyPath); e != nil {
			identity["reason"] = e.Error()
		} else {
			identity["signer_ready"] = true
		}
		decision, create := desktopLoginDecision(out, m.SID)
		identity["can_sign_in"] = create && identity["signer_ready"] == true
		identity["can_reuse"] = !create && decision["ok"] == true
		if !create && decision["ok"] != true {
			identity["blocked_by"], identity["next"] = decision["error_code"], decision["error"]
		}
	}
	out["caller_identity"] = identity
	return out, nil
}

func (s *DesktopService) loginDesktop(ctx context.Context, owner captureOwner, node, rid string, audit desktopAudit) (map[string]any, int) {
	m, keyPath, err := s.identityMapping(owner, node)
	if err != nil {
		return sessionReceipt("identity_mapping_unavailable", err.Error()), 409
	}
	status, err := s.dispatch(ctx, owner, node, map[string]any{"op": "status"}, rid, audit)
	if err != nil || status["ok"] != true {
		return sessionReceipt("session_state_unknown", "Could not inspect the current sessions"), 409
	}
	if out, create := desktopLoginDecision(status, m.SID); !create {
		if out["ok"] == true {
			return out, 200
		}
		return out, 409
	}
	key, err := desktopIdentityKey(keyPath)
	if err != nil {
		return sessionReceipt("identity_signer_unavailable", err.Error()), 409
	}
	check, ok := ctx.Value(desktopAuthorizeKey{}).(func() error)
	if !ok || check() != nil {
		return sessionReceipt("authorization_unavailable", "Fresh caller authorization is required for identity sign-in"), 403
	}
	// Challenges and grants bypass dispatch's generic receipt logging. The
	// model receives only the verified session result, never authentication data.
	response, err := s.backend(ctx, node, map[string]any{"id": newID(), "op": "identity_challenge"})
	if err != nil || response["ok"] != true {
		return sessionReceipt("identity_backend_unavailable", "Identity challenge could not be obtained"), 409
	}
	c, ok := response["challenge"].(map[string]any)
	if !ok {
		return sessionReceipt("identity_backend_unavailable", "Invalid identity challenge"), 409
	}
	grant, err := signDesktopIdentity(key, m, c, time.Now())
	if err != nil {
		return sessionReceipt("identity_signing_failed", err.Error()), 409
	}
	defer clear(grant)
	// Re-read mapping immediately before use; no fallback to a machine account.
	live, liveKey, err := s.identityMapping(owner, node)
	if err != nil || live != m || liveKey != keyPath || check() != nil {
		return sessionReceipt("authorization_changed", "Identity sign-in authorization changed"), 403
	}
	out, err := s.dispatch(ctx, owner, node, map[string]any{"op": "identity_login", "identity_grant": grant}, rid, audit)
	if err != nil {
		return map[string]any{"ok": false, "error_code": "login_outcome_unknown", "input_status": "unknown", "error": "Sign-in outcome unknown; inspect desktop_status before retrying"}, 409
	}
	if out["ok"] != true {
		return out, 409
	}
	if out["sid"] != m.SID || number(out["session_id"]) < 1 {
		return map[string]any{"ok": false, "error_code": "login_outcome_unknown", "input_status": "unknown", "error": "Sign-in receipt did not verify the mapped user; inspect desktop_status"}, 409
	}
	return out, 200
}
