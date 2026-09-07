package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Broker is XConnect's data-plane listener: RCONs reverse-dial in over raw mTLS,
// XConnect verifies + reverses the HTTP/2 roles so it can inject requests DOWN
// each node's tunnel. Cert-gated; holds no CA.
type Broker struct {
	id       *Identity
	allow    *AllowList
	tenant   string         // XConnect's own tenant — nodes must match it
	control  *ControlClient // for self-update resolution (may be nil in tests)
	tunnels  sync.Map       // svid string -> *http2.ClientConn
	versions sync.Map       // svid string -> nodeVer (running version/arch, for the report)
}

// nodeVer is a node's self-reported runtime, captured from its /health at connect
// and relayed up to Orthanc on the heartbeat report (operator version visibility).
type nodeVer struct {
	Version, GOARCH string
	Protocol        int // wire-contract version reported in /health (0 = pre-protocol node)
}

func (b *Broker) Listen(addr string) error {
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{b.id.Cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    b.id.CAPool, // pin OUR CA as the only acceptable client issuer
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13, // broker link is ours end-to-end — 1.3 only
	}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	log.Printf("broker: listening (raw mTLS, cert-gated) on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("broker: accept: %v", err)
			continue
		}
		go b.handle(conn)
	}
}

func (b *Broker) handle(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("broker: handshake from %s failed: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{}) // tunnel is long-lived
	peer := tlsConn.ConnectionState().PeerCertificates[0]
	svid := spiffeID(peer)
	spki := spkiFingerprint(peer)

	// Defense in depth: node's tenant must equal ours, AND it must be on the
	// allow-list (already tenant-scoped from the tower; absence = revoked/unknown).
	if t := tenantOf(svid); t != b.tenant {
		log.Printf("broker: REJECT %s — tenant %q != ours %q", svid, t, b.tenant)
		conn.Close()
		return
	}
	entry, ok := b.allow.Lookup(spki)
	if !ok {
		log.Printf("broker: REJECT %s — not on allow-list (revoked/unknown key)", svid)
		conn.Close()
		return
	}

	// Reverse the roles: XConnect drives HTTP/2 as the CLIENT over this conn.
	// PINGs detect a silently-stalled tunnel so we can drop dead entries fast.
	tr := &http2.Transport{ReadIdleTimeout: 15 * time.Second, PingTimeout: 15 * time.Second}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		log.Printf("broker: h2 client over %s failed: %v", svid, err)
		conn.Close()
		return
	}
	b.tunnels.Store(svid, cc)
	log.Printf("broker: TUNNEL UP %s (%s) name=%q", svid, conn.RemoteAddr(), entry.BoundName)
	go b.watchTunnel(svid, cc, conn) // reap the entry when the conn dies

	// Prove the reverse path immediately: a health check, then a real command —
	// the brain/hands round-trip over the broker.
	if body, err := b.Inject(svid, "GET", "/health", nil); err != nil {
		log.Printf("broker: %s health check failed: %v", svid, err)
	} else {
		log.Printf("broker: %s health -> %s", svid, body)
		b.recordVersion(svid, body) // cache running version/arch for the report
		// Self-update: on connect, ask the tower if this node is behind its
		// channel's target; if so, relay the SIGNED binary down the tunnel.
		if b.control != nil {
			go b.maybeUpdate(svid, body)
			go b.renewIfDue(svid) // renew the cert if it's near expiry
		}
	}
}

// recordVersion caches a node's running version/arch parsed from its /health body,
// so the heartbeat report can tell Orthanc what each node is actually running.
func (b *Broker) recordVersion(svid, healthSummary string) {
	var h struct {
		Version, GOARCH string
		Protocol        int
	}
	if i := strings.IndexByte(healthSummary, '{'); i >= 0 {
		_ = json.Unmarshal([]byte(healthSummary[i:]), &h)
	}
	if h.Version != "" || h.GOARCH != "" || h.Protocol != 0 {
		b.versions.Store(svid, nodeVer{Version: h.Version, GOARCH: h.GOARCH, Protocol: h.Protocol})
	}
}

// LiveTunnels returns the live tunnels with each node's reported version/arch —
// the payload for the control-link report (Orthanc surfaces it to operators).
func (b *Broker) LiveTunnels() []map[string]any {
	var out []map[string]any
	b.tunnels.Range(func(k, _ any) bool {
		svid := k.(string)
		m := map[string]any{"svid": svid}
		if v, ok := b.versions.Load(svid); ok {
			nv := v.(nodeVer)
			m["version"], m["goarch"] = nv.Version, nv.GOARCH
			m["protocol"] = nv.Protocol // 0 = node predates protocol reporting
		}
		out = append(out, m)
		return true
	})
	return out
}

// forceUpdate re-checks a node against its channel target and relays the signed
// binary if it's behind — the shared path for the localhost admin nudge and the
// operator-requested (pull) nudge that arrives on the report response.
func (b *Broker) forceUpdate(svid string) {
	health, err := b.Inject(svid, "GET", "/health", nil)
	if err != nil {
		log.Printf("broker: forceUpdate %s: health failed: %v", svid, err)
		return
	}
	b.maybeUpdate(svid, health)
}

// maybeUpdate parses the node's reported version from a /health summary, asks
// Orthanc (via the control link) whether an update is due for the node's
// channel, and if so relays the Orthanc-signed binary down the tunnel to
// /update/apply. RCON verifies the signature itself before applying.
func (b *Broker) maybeUpdate(svid, healthSummary string) {
	var h struct{ Version, GOOS, GOARCH string }
	if i := strings.IndexByte(healthSummary, '{'); i >= 0 {
		_ = json.Unmarshal([]byte(healthSummary[i:]), &h)
	}
	out, err := b.control.updateFor(svid, h.Version, h.GOOS, h.GOARCH)
	if err != nil {
		log.Printf("broker: %s update check failed: %v", svid, err)
		return
	}
	if upd, _ := out["update"].(bool); !upd {
		return
	}
	target, _ := out["version"].(string)
	log.Printf("broker: %s on %q -> relaying signed update %s (channel=%v)",
		svid, h.Version, target, out["channel"])
	payload, _ := json.Marshal(out) // version, goos?, goarch?, sha256, signature, binary_b64
	res, err := b.Inject(svid, "POST", "/update/apply", bytes.NewReader(payload))
	if err != nil {
		log.Printf("broker: %s update relay failed (node may be re-exec'ing): %v", svid, err)
		return
	}
	log.Printf("broker: %s update/apply -> %s", svid, res)
}

// injectResponseCap bounds a complete RCON JSON response. A /run response can
// contain separately capped stdout + stderr strings whose JSON escaping makes
// the wire body larger than either stream. Read one byte beyond the limit and
// fail closed instead of silently returning half of a JSON document.
const injectResponseCap = 16 << 20

type injectResult struct {
	StatusCode int
	Body       []byte
}

func (result injectResult) Summary() string {
	return fmt.Sprintf("HTTP %d %s", result.StatusCode, string(result.Body))
}

func readBoundedResponse(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("RCON response exceeds %d-byte broker limit", limit)
	}
	return data, nil
}

// InjectResponse sends a request down a node's reverse tunnel and returns the
// remote HTTP status and complete, bounded response body.
func (b *Broker) InjectResponse(svid, method, path string, body io.Reader) (injectResult, error) {
	v, ok := b.tunnels.Load(svid)
	if !ok {
		return injectResult{}, fmt.Errorf("no live tunnel for %s", svid)
	}
	cc := v.(*http2.ClientConn)
	req, err := http.NewRequest(method, "https://rcon"+path, body)
	if err != nil {
		return injectResult{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		// Dead conn — reap the stale entry so it stops showing as live.
		if cur, ok := b.tunnels.Load(svid); ok && cur == v {
			b.tunnels.Delete(svid)
			log.Printf("broker: TUNNEL DOWN %s — reaped on inject error: %v", svid, err)
		}
		return injectResult{}, err
	}
	defer resp.Body.Close()
	data, err := readBoundedResponse(resp.Body, injectResponseCap)
	if err != nil {
		return injectResult{}, err
	}
	return injectResult{StatusCode: resp.StatusCode, Body: data}, nil
}

// Inject preserves the historical summary interface used by health/update,
// file verbs, and the disabled local admin endpoint.
func (b *Broker) Inject(svid, method, path string, body io.Reader) (string, error) {
	result, err := b.InjectResponse(svid, method, path, body)
	if err != nil {
		return "", err
	}
	return result.Summary(), nil
}

// renewWindow: renew a node's cert once it has less than this left.
const renewWindow = 10 * 24 * time.Hour

// renewCooldown: don't auto-renew the same node again this soon — the allow-list
// lags the just-issued expiry by a heartbeat, so without this each post-renew
// reconnect would re-trigger a renewal (a brief storm).
const renewCooldown = 30 * time.Minute

var lastRenew sync.Map // svid -> time.Time of last auto-renewal

// renewNode drives a key-continuity cert renewal over the tunnel: ask the node
// for a CSR (same key), have Orthanc re-sign it, push the new cert back. The
// node hot-reloads (reconnects) with it. Forced (ignores the window) — the
// scheduler decides when to call.
func (b *Broker) renewNode(svid string) error {
	if b.control == nil {
		return fmt.Errorf("no control link")
	}
	csrResp, err := b.Inject(svid, "GET", "/renew/csr", nil)
	if err != nil {
		return fmt.Errorf("csr request: %w", err)
	}
	var csr struct {
		CSR string `json:"csr"`
	}
	if err := extractJSON(csrResp, &csr); err != nil || csr.CSR == "" {
		return fmt.Errorf("bad csr response: %s", csrResp)
	}
	out, err := b.control.signRenew(csr.CSR)
	if err != nil {
		return fmt.Errorf("control renew: %w", err)
	}
	cert, _ := out["certificate"].(string)
	if cert == "" {
		return fmt.Errorf("renew returned no certificate: %v", out)
	}
	payload, _ := json.Marshal(map[string]any{"certificate": cert})
	applyResp, err := b.Inject(svid, "POST", "/renew/apply", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	log.Printf("broker: %s cert renewed -> %s", svid, applyResp)
	return nil
}

// renewIfDue renews the node only if its allow-list cert expiry is inside the
// window. Called on tunnel-up and by the periodic sweep.
func (b *Broker) renewIfDue(svid string) {
	for _, e := range b.allow.Entries() {
		if e.SVID != svid || e.NotAfter == "" {
			continue
		}
		na, err := time.Parse(time.RFC3339, e.NotAfter)
		if err != nil {
			return
		}
		if time.Until(na) < renewWindow {
			if v, ok := lastRenew.Load(svid); ok {
				if t, _ := v.(time.Time); time.Since(t) < renewCooldown {
					return // renewed very recently; allow-list just hasn't caught up
				}
			}
			log.Printf("broker: %s cert expires %s — renewing (window %s)", svid, e.NotAfter, renewWindow)
			if err := b.renewNode(svid); err != nil {
				log.Printf("broker: %s renew failed: %v", svid, err)
			} else {
				lastRenew.Store(svid, time.Now())
			}
		}
		return
	}
}

// renewSweep periodically renews every live tunnel whose cert is near expiry —
// covers long-lived connections that never reconnect.
func (b *Broker) renewSweep() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		b.tunnels.Range(func(k, _ any) bool {
			go b.renewIfDue(k.(string))
			return true
		})
	}
}

func extractJSON(s string, v any) error {
	i := strings.IndexByte(s, '{')
	if i < 0 {
		return fmt.Errorf("no json in %q", s)
	}
	return json.Unmarshal([]byte(s[i:]), v)
}

// reconcile drops any LIVE tunnel whose node is no longer on the allow-list
// (revoked or removed at the tower). Called after every allow-list refresh, so
// revocation kills an established tunnel — not just blocks the next reconnect
// (the handshake already refuses an off-list node). This is the "revoke-now"
// enforcement, bounded by the heartbeat interval; the forced admin /reconcile
// path makes it instant.
//
// Empty-list resilience lives in AllowList.Replace now: a zero-length snapshot
// is the signature of a control-plane hiccup (or a forged response), NOT a
// deliberate revoke-everything, so it's rejected (last-known-good retained)
// rather than applied. reconcile therefore always runs against an authoritative,
// non-empty list once loaded — it actively enforces (no fail-open blind spot).
//
// Renewal-safe: renewal preserves both SPKI (allow-list key) and SVID (tunnel
// key), so a node mid-renewal is never falsely dropped.
func (b *Broker) reconcile() {
	// Cold-start guard: before the first non-empty snapshot loads, we have no
	// authoritative list — don't drop anything. (A spurious empty AFTER load is
	// already rejected by AllowList.Replace, so entries here is authoritative.)
	if !b.allow.Loaded() {
		return
	}
	entries := b.allow.Entries()
	allowed := make(map[string]bool, len(entries))
	for _, e := range entries {
		allowed[e.SVID] = true
	}
	b.tunnels.Range(func(k, v any) bool {
		svid := k.(string)
		if allowed[svid] {
			return true
		}
		cc := v.(*http2.ClientConn)
		b.tunnels.Delete(svid)
		b.versions.Delete(svid)
		_ = cc.Close() // tears down the conn; the node's reconnect is then refused at handshake
		log.Printf("broker: REVOKED %s — dropped live tunnel (off the allow-list)", svid)
		return true
	})
}

// refreshAndReconcile pulls a fresh allow-list and enforces it immediately —
// the forced "revoke now" path behind the admin /reconcile hook.
func (b *Broker) refreshAndReconcile() error {
	if b.control == nil {
		return fmt.Errorf("no control link")
	}
	t, nodes, err := b.control.fetchAllowList()
	if err != nil {
		return err
	}
	if !b.allow.Replace(t, nodes) {
		log.Printf("broker: refresh returned an EMPTY allow-list — retaining last-known-good (not applying)")
	}
	b.reconcile()
	return nil
}

// watchTunnel pings the reverse tunnel periodically and removes the entry when
// the conn dies — so list_remote_hosts / liveness never advertise a dead node.
func (b *Broker) watchTunnel(svid string, cc *http2.ClientConn, conn net.Conn) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for range t.C {
		// Stop if this entry was replaced (reconnect) or already removed.
		if v, ok := b.tunnels.Load(svid); !ok || v != cc {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := cc.Ping(ctx)
		cancel()
		if err != nil {
			if v, ok := b.tunnels.Load(svid); ok && v == cc {
				b.tunnels.Delete(svid)
				b.versions.Delete(svid)
				log.Printf("broker: TUNNEL DOWN %s — reaped (ping failed: %v)", svid, err)
			}
			_ = conn.Close()
			return
		}
	}
}

// LiveSVIDs returns the node SVIDs with a currently-registered tunnel.
func (b *Broker) LiveSVIDs() []string {
	var out []string
	b.tunnels.Range(func(k, _ any) bool { out = append(out, k.(string)); return true })
	return out
}

// HostInfo is one reachable node, as a human would refer to it.
type HostInfo struct {
	Name        string `json:"name"`        // operator-assigned bound_name (may be an opaque hostname)
	Description string `json:"description"` // operator-set human role ("the database box") — maps intent→node
	SVID        string `json:"svid"`        // full SPIFFE id
	NodeID      string `json:"node_id"`     // the uuid tail of the SVID — the unambiguous target
	Online      bool   `json:"online"`
}

// LiveHosts correlates the live tunnels with the allow-list so callers see
// human names + descriptions instead of bare SPIFFE GUIDs.
func (b *Broker) LiveHosts() []HostInfo {
	meta := map[string]NodeEntry{}
	for _, e := range b.allow.Entries() {
		meta[e.SVID] = e
	}
	var out []HostInfo
	b.tunnels.Range(func(k, _ any) bool {
		svid := k.(string)
		e := meta[svid]
		out = append(out, HostInfo{
			Name: e.BoundName, Description: e.Description,
			SVID: svid, NodeID: nodeIDOf(svid), Online: true,
		})
		return true
	})
	return out
}

// AllHosts returns every node on the allow-list (i.e. every ACTIVE node for this
// tenant) as a HostInfo, with Online reflecting whether a tunnel is live right
// now. Unlike LiveHosts (data-plane: only connected nodes), this is for
// control-plane lookups — node knowledge must resolve a target even when offline.
func (b *Broker) AllHosts() []HostInfo {
	out := make([]HostInfo, 0, b.allow.Size())
	for _, e := range b.allow.Entries() {
		_, online := b.tunnels.Load(e.SVID)
		out = append(out, HostInfo{
			Name: e.BoundName, Description: e.Description,
			SVID: e.SVID, NodeID: nodeIDOf(e.SVID), Online: online,
		})
	}
	return out
}

// nodeIDOf extracts the uuid tail from spiffe://…/node/<uuid>.
func nodeIDOf(svid string) string {
	parts := strings.Split(strings.TrimRight(svid, "/"), "/")
	return parts[len(parts)-1]
}
