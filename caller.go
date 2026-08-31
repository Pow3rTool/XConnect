package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Caller webservice — the friendly Caller/MCP ingress (the "443 webservice").
// It validates the OBO token, asks Orthanc to authorize the (principal, verb),
// and injects to the target RCON tunnel. The verbs mirror the CLI worker
// primitives (run/jobs/read/edit/write) on purpose — same premise, same
// safeguards (output caps + job model come from the RCON; authZ + audit here).
type Caller struct {
	broker   *Broker
	control  *ControlClient
	validate func(string) (*principal, error)
	calls    *CallLog // audit buffer; shipped to Orthanc on the heartbeat
}

// detailMax bounds the command/path summary we keep per audit event.
const detailMax = 2000

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// record stamps and buffers a call event (no-op if no buffer wired).
func (cl *Caller) record(ev *callEvent) {
	if cl.calls != nil {
		cl.calls.Add(*ev)
	}
}

// recordStart ships a "start" marker for an authorized call we are about to
// inject, so the console shows it as RUNNING until the terminal event (same
// RequestID) clears it. Same buffer + ~200ms ship path as the audit events, so a
// long-running command surfaces within a fraction of a second of starting. Only
// the identity/target fields are carried — never an outcome (there isn't one yet).
func (cl *Caller) recordStart(ev *callEvent) {
	if cl.calls == nil {
		return
	}
	cl.calls.Add(callEvent{
		Phase: "start", RequestID: ev.RequestID, TS: ev.TS,
		UPN: ev.UPN, OID: ev.OID, TID: ev.TID, App: ev.App, AppName: ev.AppName,
		Verb: ev.Verb, Node: ev.Node, SVID: ev.SVID, Detail: ev.Detail,
	})
}

type principal struct {
	UPN  string
	OID  string
	TID  string
	Name string
	// AppID / AppName identify the AGENT — the OAuth client app that obtained this
	// token on the user's behalf (OBO `azp`/`appid`, with `app_displayname` for the
	// friendly name). Lets an operator tell WHICH of an admin's several agents made
	// a call, not just which human it ran as.
	AppID   string
	AppName string
	Scopes  []string
	Groups  []string
	Raw     string // the validated OBO bearer, forwarded to Orthanc for INDEPENDENT re-validation
}

const requiredScope = "tunnel.invoke"

// newValidator builds the token check. mode "entra" verifies RS256 against the
// tenant JWKS; mode "dev" verifies an HS256 dev token (headless testing only).
func newValidator(mode, tenantID, audience, devSecret string) func(string) (*principal, error) {
	// v2-only by policy: the tenant v2.0 issuer is the ONLY accepted form.
	// A v1 STS issuer (https://sts.windows.net/<tid>/) means the API app
	// registration is still minting legacy tokens — fix it at the source by
	// setting api.requestedAccessTokenVersion=2 on the XConnect API app,
	// not by loosening this check.
	issuerV2 := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)

	var keyf jwt.Keyfunc
	var methods []string
	if mode == "dev" {
		// HARD STOP: an empty/weak HS256 secret means anyone can forge a token
		// (the empty-key bypass). Refuse to start rather than serve a wide-open
		// door. Dev mode is for headless testing only and must be opted into
		// explicitly with a strong secret.
		if len(devSecret) < 32 {
			log.Fatalf("caller: auth-mode=dev requires XCONNECT_DEV_SECRET of >=32 bytes; " +
				"refusing to start (an empty/weak secret lets anyone forge tokens). " +
				"Use auth-mode=entra in production.")
		}
		secret := []byte(devSecret)
		keyf = func(*jwt.Token) (any, error) { return secret, nil }
		methods = []string{"HS256"}
		log.Printf("caller: AUTH MODE = dev (HS256 test tokens) — NOT for production")
	} else {
		k, err := keyfunc.NewDefault([]string{jwksURL})
		if err != nil {
			log.Fatalf("caller: JWKS init failed: %v", err)
		}
		keyf = k.Keyfunc
		methods = []string{"RS256"}
		log.Printf("caller: AUTH MODE = entra (RS256 via %s)", jwksURL)
	}

	return func(tokenStr string) (*principal, error) {
		// Issuer is validated manually below (two accepted forms), so don't
		// pin a single issuer here.
		opts := []jwt.ParserOption{jwt.WithValidMethods(methods), jwt.WithExpirationRequired()}
		tok, err := jwt.Parse(tokenStr, keyf, opts...)
		if err != nil {
			return nil, fmt.Errorf("token invalid: %w", err)
		}
		claims, _ := tok.Claims.(jwt.MapClaims)

		// Diagnostic: surface the identity-shaping claims so issuer/audience/
		// version mismatches are obvious in the log.
		log.Printf("caller: token claims iss=%q aud=%v ver=%v scp=%q upn=%q tid=%q azp=%q app=%q",
			asStr(claims["iss"]), claims["aud"], claims["ver"],
			asStr(claims["scp"]), firstNonEmpty(asStr(claims["preferred_username"]), asStr(claims["upn"])),
			asStr(claims["tid"]),
			firstNonEmpty(asStr(claims["azp"]), asStr(claims["appid"])),
			asStr(claims["app_displayname"]))

		if mode != "dev" {
			iss := asStr(claims["iss"])
			if iss != issuerV2 {
				return nil, fmt.Errorf("issuer %q is not the tenant v2 issuer %q "+
					"(set api.requestedAccessTokenVersion=2 on the XConnect API app)", iss, issuerV2)
			}
		}

		// Audience: accept the App ID URI or the bare app-id guid.
		if !audienceOK(claims["aud"], audience) {
			return nil, fmt.Errorf("wrong audience")
		}
		scopes := strings.Fields(asStr(claims["scp"]))
		if !contains(scopes, requiredScope) {
			return nil, fmt.Errorf("missing scope %q", requiredScope)
		}
		upn := asStr(claims["preferred_username"])
		if upn == "" {
			upn = asStr(claims["upn"])
		}
		return &principal{
			UPN: upn, OID: asStr(claims["oid"]), TID: asStr(claims["tid"]),
			Name:    asStr(claims["name"]),
			AppID:   firstNonEmpty(asStr(claims["azp"]), asStr(claims["appid"])),
			AppName: asStr(claims["app_displayname"]),
			Scopes:  scopes, Groups: toStrings(claims["groups"]),
			Raw: tokenStr, // forwarded so Orthanc re-validates against Entra, not our word
		}, nil
	}
}

func (cl *Caller) Serve(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/run", cl.verbHandler("run", "/run"))
	mux.HandleFunc("POST /v1/jobs", cl.verbHandler("run", "/jobs"))
	mux.HandleFunc("GET /v1/whoami", cl.whoamiHandler)
	mux.HandleFunc("POST /v1/whoami", cl.whoamiHandler)
	mux.HandleFunc("GET /v1/hosts", cl.hostsHandler)
	// read/edit/write are authorized here but not yet on the Go RCON (501).
	mux.HandleFunc("POST /v1/read", cl.fileVerbHandler("read", "/read"))
	mux.HandleFunc("POST /v1/edit", cl.fileVerbHandler("full", "/edit"))
	mux.HandleFunc("POST /v1/write", cl.fileVerbHandler("full", "/write"))
	// Node knowledge (the shared "wiki for agents") — relayed up the control link
	// to Orthanc/Postgres; XConnect never touches the DB. search needs the
	// knowledge_read verb (readonly), append needs knowledge_write (full).
	mux.HandleFunc("POST /v1/knowledge/search", cl.knowledgeHandler(false))
	mux.HandleFunc("POST /v1/knowledge/append", cl.knowledgeHandler(true))
	log.Printf("caller: webservice on %s (/v1/run, /v1/jobs)", addr)
	if err := hardenedServe(addr, mux); err != nil {
		log.Printf("caller: %v", err)
	}
}

// verbHandler validates the token, authorizes (principal, verb) at Orthanc, then
// injects to the named node's tunnel.
func (cl *Caller) verbHandler(verb, rconPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := cl.auth(r)
		if err != nil {
			callerJSON(w, 401, map[string]any{"error": err.Error()})
			return // pre-perimeter, no principal — not an audit event
		}
		// One audit event per authenticated call, finalized at return. Mutated as
		// the call progresses; the defer captures the final state (incl. outcome).
		ev := callEvent{TS: nowRFC3339(), RequestID: newID(),
			UPN: p.UPN, OID: p.OID, TID: p.TID, App: p.AppID, AppName: p.AppName, Verb: verb}
		defer func() {
			log.Printf("CALL principal=%s app=%s verb=%s target=%s allowed=%v status=%s (%s)",
				ev.UPN, ev.App, ev.Verb, ev.Node, ev.Allowed, ev.Status, ev.Reason)
			cl.record(&ev)
		}()

		var body struct {
			Node string `json:"node"`
			Cmd  string `json:"cmd"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ev.Node, ev.Detail = body.Node, clip(body.Cmd, detailMax)
		if body.Node == "" {
			ev.Status = "bad-request"
			callerJSON(w, 400, map[string]any{"error": "node required"})
			return
		}
		// THE PERIMETER: even a valid token is gated per principal+verb at Orthanc.
		allowed, reason, err := cl.control.authorize(p, verb)
		if err != nil {
			ev.Status = "error:authz-unavailable"
			callerJSON(w, 502, map[string]any{"error": "authz unavailable: " + err.Error()})
			return
		}
		ev.Allowed, ev.Reason = allowed, reason
		svid, candidates := cl.broker.resolveTarget(body.Node)
		ev.SVID = svid
		if !allowed {
			ev.Status = "denied"
			callerJSON(w, 403, map[string]any{"error": "not authorized", "reason": reason})
			return
		}
		if svid == "" {
			if len(candidates) > 0 {
				// Ambiguous on purpose-built fleets: never guess. Hand back the
				// matches so the caller re-issues with an exact node_id.
				ev.Status = "ambiguous"
				callerJSON(w, 409, map[string]any{
					"error": fmt.Sprintf("%q matches %d nodes — re-issue with an exact node_id from candidates",
						body.Node, len(candidates)),
					"candidates": candidates,
				})
				return
			}
			ev.Status = "no-tunnel"
			callerJSON(w, 404, map[string]any{"error": "no live tunnel for node " + body.Node})
			return
		}
		// Past the perimeter with a live tunnel: the call is now executing. Mark it
		// running so the console shows it until Inject returns. We carry the
		// RequestID into the RCON body too (correlation token, NOT the principal —
		// the node's audit stays a "what ran here" view; the "who" is the Witchhunt).
		cl.recordStart(&ev)
		var payload io.Reader
		if body.Cmd != "" {
			payload = strings.NewReader(fmt.Sprintf(`{"cmd":%q,"rid":%q}`, body.Cmd, ev.RequestID))
		}
		out, err := cl.broker.Inject(svid, "POST", rconPath, payload)
		if err != nil {
			ev.Status = "error:inject"
			callerJSON(w, 502, map[string]any{"error": err.Error()})
			return
		}
		ev.Status = "ok"
		ev.captureResult(out) // store what the call DID for drill-down
		if r.Context().Err() != nil {
			// The caller disconnected while the node was still running. The command
			// DID complete and we captured its result (status stays ok) — note the
			// disconnect so the audit is honest about who was/wasn't listening.
			ev.Reason = "caller disconnected before response"
		}
		callerJSON(w, 200, map[string]any{"principal": p.UPN, "node": svid,
			"result": out, "dur_ms": ev.DurMs})
	}
}

// writeMetadataRequested detects the additive write capability without trying
// to validate its values (RCON is the filesystem authority and performs that
// validation). Non-string values still count as a request, so they take the
// fail-closed endpoint and are rejected by RCON's typed JSON decoder.
func writeMetadataRequested(body map[string]any) bool {
	for _, key := range []string{"owner", "group", "mode"} {
		value, ok := body[key]
		if !ok || value == nil {
			continue
		}
		if s, ok := value.(string); !ok || strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

func metadataEndpointUnsupported(injectOut string) bool {
	return strings.HasPrefix(injectOut, "HTTP 404 ")
}

// fileVerbHandler forwards a file primitive (read/edit/write) to the node:
// authorize (principal, verb) at Orthanc, resolve the target, then relay the
// request body (minus "node") straight to the RCON path — so path / content /
// old_string / expected_hash pass through unchanged. read needs the "read" verb
// class; edit/write need "full".
func (cl *Caller) fileVerbHandler(verb, rconPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := cl.auth(r)
		if err != nil {
			callerJSON(w, 401, map[string]any{"error": err.Error()})
			return
		}
		ev := callEvent{TS: nowRFC3339(), RequestID: newID(),
			UPN: p.UPN, OID: p.OID, TID: p.TID, App: p.AppID, AppName: p.AppName, Verb: verb}
		defer func() {
			log.Printf("CALL principal=%s app=%s verb=%s target=%s allowed=%v status=%s (%s)",
				ev.UPN, ev.App, ev.Verb, ev.Node, ev.Allowed, ev.Status, ev.Reason)
			cl.record(&ev)
		}()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
			ev.Status = "bad-request"
			callerJSON(w, 400, map[string]any{"error": "body must be a JSON object"})
			return
		}
		node, _ := body["node"].(string)
		ev.Node = node
		if path, ok := body["path"].(string); ok {
			ev.Detail = clip(path, detailMax) // the file primitive's target path
		}
		if node == "" {
			ev.Status = "bad-request"
			callerJSON(w, 400, map[string]any{"error": "node required"})
			return
		}
		allowed, reason, err := cl.control.authorize(p, verb)
		if err != nil {
			ev.Status = "error:authz-unavailable"
			callerJSON(w, 502, map[string]any{"error": "authz unavailable: " + err.Error()})
			return
		}
		ev.Allowed, ev.Reason = allowed, reason
		svid, candidates := cl.broker.resolveTarget(node)
		ev.SVID = svid
		if !allowed {
			ev.Status = "denied"
			callerJSON(w, 403, map[string]any{"error": "not authorized", "reason": reason})
			return
		}
		if svid == "" {
			if len(candidates) > 0 {
				ev.Status = "ambiguous"
				callerJSON(w, 409, map[string]any{
					"error":      fmt.Sprintf("%q matches %d nodes — re-issue with an exact node_id from candidates", node, len(candidates)),
					"candidates": candidates})
				return
			}
			ev.Status = "no-tunnel"
			callerJSON(w, 404, map[string]any{"error": "no live tunnel for node " + node})
			return
		}
		targetPath := rconPath
		metadataWrite := rconPath == "/write" && writeMetadataRequested(body)
		if metadataWrite {
			// A separate additive endpoint makes older RCONs fail closed with
			// 404 instead of silently ignoring unknown owner/group/mode fields.
			targetPath = "/write-metadata"
		}
		// Past the perimeter with a live tunnel: mark it running and carry the
		// RequestID into the RCON body (correlation token only, never the principal).
		cl.recordStart(&ev)
		delete(body, "node")
		body["rid"] = ev.RequestID
		raw, _ := json.Marshal(body)
		out, err := cl.broker.Inject(svid, "POST", targetPath, bytes.NewReader(raw))
		if err != nil {
			ev.Status = "error:inject"
			callerJSON(w, 502, map[string]any{"error": err.Error()})
			return
		}
		if metadataWrite && metadataEndpointUnsupported(out) {
			ev.Status = "unsupported"
			ev.captureResult(out)
			callerJSON(w, 409, map[string]any{
				"error": "target RCON does not support remote_write owner/group/mode; update the node first",
				"node":  svid,
			})
			return
		}
		ev.Status = "ok"
		ev.captureResult(out)
		if r.Context().Err() != nil {
			ev.Reason = "caller disconnected before response"
		}
		callerJSON(w, 200, map[string]any{"principal": p.UPN, "node": svid,
			"result": out, "dur_ms": ev.DurMs})
	}
}

// knowledgeHandler relays a node-knowledge search/append to Orthanc over the
// control link. write=false → search (verb knowledge_read); write=true → append
// (verb knowledge_write, needs `full`). Orthanc authorizes the principal AND
// stamps provenance server-side, so we only forward identity + payload. The node
// is resolved over the ALLOW-LIST (resolveKnown), so knowledge works even when
// the node's tunnel is down — it's control-plane, not data-plane.
func (cl *Caller) knowledgeHandler(write bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := cl.auth(r)
		if err != nil {
			callerJSON(w, 401, map[string]any{"error": err.Error()})
			return
		}
		verb := "knowledge_read"
		if write {
			verb = "knowledge_write"
		}
		ev := callEvent{TS: nowRFC3339(), UPN: p.UPN, OID: p.OID, TID: p.TID, Verb: verb}
		defer func() {
			log.Printf("KNOWLEDGE principal=%s verb=%s target=%s allowed=%v status=%s",
				ev.UPN, ev.Verb, ev.Node, ev.Allowed, ev.Status)
			cl.record(&ev)
		}()
		var body struct {
			Node    string `json:"node"`
			Query   string `json:"query"`
			Content string `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ev.Node = body.Node
		if write {
			ev.Detail = clip(body.Content, detailMax)
		} else {
			ev.Detail = clip(body.Query, detailMax)
		}
		if body.Node == "" {
			ev.Status = "bad-request"
			callerJSON(w, 400, map[string]any{"error": "node required"})
			return
		}
		if write && strings.TrimSpace(body.Content) == "" {
			ev.Status = "bad-request"
			callerJSON(w, 400, map[string]any{"error": "content required for append"})
			return
		}
		// AuthZ BEFORE resolving the node: resolveKnown can echo back node
		// names/descriptions/SVIDs as ambiguity candidates, so an authenticated-but-
		// unauthorized (or jailed-agent) principal must be denied here — matching the
		// hostsHandler pattern — rather than leaking the tenant's node inventory.
		// The knowledge control endpoint re-authorizes too; this is the front gate.
		allowed, reason, err := cl.control.authorize(p, verb)
		if err != nil {
			ev.Status = "error:control"
			callerJSON(w, 502, map[string]any{"error": "authz unavailable: " + err.Error()})
			return
		}
		if !allowed {
			ev.Status = "denied"
			ev.Reason = reason
			callerJSON(w, 403, map[string]any{"error": "not authorized", "reason": reason})
			return
		}
		svid, candidates := cl.broker.resolveKnown(body.Node)
		ev.SVID = svid
		if svid == "" {
			if len(candidates) > 0 {
				ev.Status = "ambiguous"
				callerJSON(w, 409, map[string]any{
					"error": fmt.Sprintf("%q matches %d nodes — re-issue with an exact node_id from candidates",
						body.Node, len(candidates)),
					"candidates": candidates})
				return
			}
			ev.Status = "no-tunnel"
			callerJSON(w, 404, map[string]any{"error": "no such node " + body.Node})
			return
		}
		var out map[string]any
		if write {
			out, err = cl.control.knowledgeAppend(p, svid, body.Content)
		} else {
			out, err = cl.control.knowledgeSearch(p, svid, body.Query)
		}
		if err != nil {
			// Orthanc returns 403 (not authorized) / 400 (bad request) as control
			// errors; surface the tower's reason rather than a blanket 502.
			code := 502
			ev.Status = "error:control"
			if out != nil {
				if reason, ok := out["reason"]; ok {
					code = 403
					ev.Status = "denied"
					ev.Reason, _ = reason.(string)
				} else if _, ok := out["error"]; ok {
					code = 400
					ev.Status = "bad-request"
				}
			}
			if out == nil {
				out = map[string]any{"error": err.Error()}
			}
			callerJSON(w, code, out)
			return
		}
		ev.Allowed, ev.Status = true, "ok"
		callerJSON(w, 200, out)
	}
}

// whoamiHandler echoes the OBO identity (as XConnect validated it) + the authZ
// Orthanc has granted the principal. Debug aid for the per-user OBO path.
func (cl *Caller) whoamiHandler(w http.ResponseWriter, r *http.Request) {
	p, err := cl.auth(r)
	if err != nil {
		callerJSON(w, 401, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{
		"principal": map[string]any{
			"upn": p.UPN, "oid": p.OID, "tenant_id": p.TID,
			"scopes": p.Scopes, "groups": p.Groups,
		},
	}
	if az, err := cl.control.whoami(p); err != nil {
		resp["authorization_error"] = err.Error()
	} else {
		resp["authorization"] = az // {tenant, grants, effective_verb_class, default_deny}
	}
	callerJSON(w, 200, resp)
}

// hostsHandler lists the node tunnels currently live to this broker (the
// nodes the principal could target). Auth-gated but not verb-gated — it's
// discovery, mirroring the CLI worker's host list.
func (cl *Caller) hostsHandler(w http.ResponseWriter, r *http.Request) {
	p, err := cl.auth(r)
	if err != nil {
		callerJSON(w, 401, map[string]any{"error": err.Error()})
		return
	}
	// AuthZ: host discovery still reveals node names/descriptions/SVIDs, so gate it
	// behind at least a readonly grant (verb "list" → readonly class at Orthanc) —
	// a valid token alone is not enough. Default-deny if Orthanc is unreachable.
	allowed, reason, err := cl.control.authorize(p, "list")
	if err != nil {
		callerJSON(w, 502, map[string]any{"error": "authz unavailable: " + err.Error()})
		return
	}
	if !allowed {
		callerJSON(w, 403, map[string]any{"error": "not authorized", "reason": reason})
		return
	}
	// Scale: a tenant may have hundreds/thousands of nodes. Filter server-side
	// (by name or SVID substring) and bound the page so we never dump the whole
	// fleet into a caller's context. total_matched/total_online tell the caller
	// whether to narrow further.
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	all := cl.broker.LiveHosts()
	matched := make([]HostInfo, 0, len(all))
	for _, h := range all {
		if q == "" || strings.Contains(strings.ToLower(h.Name), q) ||
			strings.Contains(strings.ToLower(h.Description), q) ||
			strings.Contains(strings.ToLower(h.SVID), q) {
			matched = append(matched, h)
		}
	}
	total := len(matched)
	truncated := false
	if len(matched) > limit {
		matched = matched[:limit]
		truncated = true
	}
	callerJSON(w, 200, map[string]any{
		"principal": p.UPN, "filter": q,
		"count": len(matched), "total_matched": total, "total_online": len(all),
		"truncated": truncated, "hosts": matched,
	})
}

func (cl *Caller) notImplemented(verb string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := cl.auth(r); err != nil {
			callerJSON(w, 401, map[string]any{"error": err.Error()})
			return
		}
		callerJSON(w, 501, map[string]any{"error": "verb not yet implemented on the Go RCON"})
	}
}

func (cl *Caller) auth(r *http.Request) (*principal, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, fmt.Errorf("missing bearer token")
	}
	return cl.validate(strings.TrimPrefix(h, "Bearer "))
}

// audienceOK accepts a comma-separated allow-list in `want`. This covers both
// audience forms an Entra token can carry: the App ID URI (v1 access tokens)
// and the bare resource appId GUID (v2 access tokens). Each entry also matches
// with any "api://" prefix stripped.
func audienceOK(aud any, want string) bool {
	var accepted []string
	for _, w := range strings.Split(want, ",") {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		accepted = append(accepted, w, strings.TrimPrefix(w, "api://"))
	}
	check := func(s string) bool {
		for _, a := range accepted {
			if s == a {
				return true
			}
		}
		return false
	}
	switch v := aud.(type) {
	case string:
		return check(v)
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && check(s) {
				return true
			}
		}
	}
	return false
}

func asStr(v any) string { s, _ := v.(string); return s }
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}
func toStrings(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func callerJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var _ = time.Now // keep time imported for future token-age logging
