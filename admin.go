package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ServeAdmin is an UNAUTHENTICATED ops hook to drive tunnels by hand (/call,
// /renew, /update, /reconcile = full fleet control, OAuth-bypassing). It defaults
// to a Unix socket (0600, root-only) so it's unreachable by SSRF-to-localhost or
// a co-tenant sharing loopback — filesystem perms are its gate. A loopback
// host:port is still accepted (legacy), but a non-loopback bind is refused.
func (b *Broker) ServeAdmin(addr string) {
	mux := http.NewServeMux()

	mux.HandleFunc("/tunnels", func(w http.ResponseWriter, r *http.Request) {
		hosts := b.LiveHosts()
		writeJSONAdmin(w, 200, map[string]any{"count": len(hosts), "tunnels": hosts})
	})

	// Nudge a node to check for a self-update NOW (the "tell my dev servers an
	// upgrade is available" trigger) instead of waiting for its next reconnect.
	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		svid := b.matchTunnel(r.URL.Query().Get("node"))
		if svid == "" {
			writeJSONAdmin(w, 404, map[string]any{"error": "no live tunnel matching node"})
			return
		}
		go b.forceUpdate(svid) // health-check + relay the signed binary if behind
		writeJSONAdmin(w, 200, map[string]any{"nudged": svid})
	})

	// Force a cert renewal on a node now (ops/testing; bypasses the expiry window).
	mux.HandleFunc("/renew", func(w http.ResponseWriter, r *http.Request) {
		svid := b.matchTunnel(r.URL.Query().Get("node"))
		if svid == "" {
			writeJSONAdmin(w, 404, map[string]any{"error": "no live tunnel matching node"})
			return
		}
		if err := b.renewNode(svid); err != nil {
			writeJSONAdmin(w, 502, map[string]any{"error": err.Error(), "node": svid})
			return
		}
		writeJSONAdmin(w, 200, map[string]any{"renewed": svid})
	})

	// Force an allow-list refresh + reconcile NOW — instant revoke enforcement
	// (drops any live tunnel whose node was just revoked) without waiting for the
	// next heartbeat. The console revoke action can call this for snappy kills.
	mux.HandleFunc("/reconcile", func(w http.ResponseWriter, r *http.Request) {
		before := len(b.LiveSVIDs())
		if err := b.refreshAndReconcile(); err != nil {
			writeJSONAdmin(w, 502, map[string]any{"error": err.Error()})
			return
		}
		after := b.LiveSVIDs()
		writeJSONAdmin(w, 200, map[string]any{
			"reconciled": true, "tunnels_before": before,
			"tunnels_after": len(after), "dropped": before - len(after), "live": after})
	})

	mux.HandleFunc("/call", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Node, Method, Path, Body string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONAdmin(w, 400, map[string]any{"error": err.Error()})
			return
		}
		svid := b.matchTunnel(req.Node)
		if svid == "" {
			writeJSONAdmin(w, 404, map[string]any{"error": "no live tunnel matching " + req.Node})
			return
		}
		method := req.Method
		if method == "" {
			method = "GET"
		}
		var body io.Reader
		if req.Body != "" {
			body = strings.NewReader(req.Body)
		}
		out, err := b.Inject(svid, method, req.Path, body)
		if err != nil {
			writeJSONAdmin(w, 502, map[string]any{"error": err.Error(), "node": svid})
			return
		}
		writeJSONAdmin(w, 200, map[string]any{"node": svid, "result": out})
	})

	// Unix socket (preferred): filesystem-perm gated, no loopback TCP surface.
	if strings.HasPrefix(addr, "/") {
		_ = os.Remove(addr) // clear a stale socket from a previous run
		ln, err := net.Listen("unix", addr)
		if err != nil {
			log.Printf("admin: listen %s: %v", addr, err)
			return
		}
		if err := os.Chmod(addr, 0o600); err != nil {
			log.Printf("admin: chmod %s: %v", addr, err)
		}
		log.Printf("admin: unix socket %s (0600, root-only) — /tunnels, /call", addr)
		srv := &http.Server{
			Handler:           limitBody(mux, 4<<20),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		if err := srv.Serve(ln); err != nil {
			log.Printf("admin: %v", err)
		}
		return
	}
	// Legacy loopback TCP — still never a non-loopback bind.
	if !isLoopbackAddr(addr) {
		log.Fatalf("admin: refusing to bind non-loopback address %q — the admin API is "+
			"unauthenticated; use a unix socket path or a loopback host:port", addr)
	}
	log.Printf("admin: loopback API on %s (prefer a unix socket path for --admin-addr)", addr)
	if err := hardenedServe(addr, mux); err != nil {
		log.Printf("admin: %v", err)
	}
}

// resolveTarget maps a caller-supplied node reference to ONE live tunnel,
// collision-safe so a fleet of opaquely-named nodes can never resolve to the
// wrong box. Returns:
//   - (svid, nil)         exactly one match — go.
//   - ("", candidates)    the reference is ambiguous; caller must re-issue with
//                         an exact node_id from the candidate list.
//   - ("", nil)           nothing live matches.
//
// Resolution prefers the unambiguous identifiers an agent is told to use:
//  1. exact full SVID, or exact node_id (uuid) — always unique.
//  2. exact bound_name (case-insensitive) — unique iff names are unique.
//  3. substring across name / description / SVID — discovery convenience.
// At each tier, >1 live match returns the candidates instead of guessing.
func (b *Broker) resolveTarget(q string) (string, []HostInfo) {
	return resolveAmong(q, b.LiveHosts())
}

// resolveKnown is resolveTarget's control-plane sibling: it resolves over the
// ALLOW-LIST (every active node for the tenant), not just live tunnels — so node
// knowledge can be read/appended even when the box is offline. Same collision
// safety: a unique match or candidates, never a guess.
func (b *Broker) resolveKnown(q string) (string, []HostInfo) {
	return resolveAmong(q, b.AllHosts())
}

// resolveAmong is the shared, collision-safe resolver over a set of hosts.
func resolveAmong(q string, hosts []HostInfo) (string, []HostInfo) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", nil
	}
	live := hosts
	// 1. Exact, inherently-unique identifiers.
	for _, h := range live {
		if q == h.SVID || strings.EqualFold(q, h.NodeID) {
			return h.SVID, nil
		}
	}
	// 2. Exact name.
	var nameHits []HostInfo
	for _, h := range live {
		if h.Name != "" && strings.EqualFold(h.Name, q) {
			nameHits = append(nameHits, h)
		}
	}
	if len(nameHits) == 1 {
		return nameHits[0].SVID, nil
	}
	if len(nameHits) > 1 {
		return "", nameHits
	}
	// 3. Substring across name/description/SVID.
	ql := strings.ToLower(q)
	var subHits []HostInfo
	for _, h := range live {
		if strings.Contains(strings.ToLower(h.Name), ql) ||
			strings.Contains(strings.ToLower(h.Description), ql) ||
			strings.Contains(strings.ToLower(h.SVID), ql) {
			subHits = append(subHits, h)
		}
	}
	if len(subHits) == 1 {
		return subHits[0].SVID, nil
	}
	return "", subHits // 0 → not found; >1 → ambiguous candidates
}

// matchTunnel is the thin, ops-facing wrapper used by the admin /call hook:
// returns the SVID only on a UNIQUE match (empty on none-or-ambiguous, which is
// the safe choice for an unauthenticated local tool).
func (b *Broker) matchTunnel(q string) string {
	svid, _ := b.resolveTarget(q)
	return svid
}

func writeJSONAdmin(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
