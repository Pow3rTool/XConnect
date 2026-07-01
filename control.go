package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ControlClient is XConnect's mutually-pinned link UP to the Orthanc tower.
// XConnect always dials out (NAT/firewall-friendly, contained blast radius);
// the tower never dials in. Both sides verify by SPIFFE identity against the
// pinned CA, not by hostname or the system trust store.
type ControlClient struct {
	http    *http.Client
	baseURL string
	// instanceID is this XConnect process's incarnation id (set once at serve
	// start). Sent on report/calllog so the tower can clear the "running" rows of
	// a prior incarnation after a restart — they can't still be executing.
	instanceID string
}

func newControlClient(id *Identity, baseURL, expectedServerID string) *ControlClient {
	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("control server presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			if c, err := x509.ParseCertificate(raw); err == nil {
				intermediates.AddCert(c)
			}
		}
		// Pin OUR anchor; the system trust store is deliberately ignored.
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: id.CAPool, Intermediates: intermediates}); err != nil {
			return fmt.Errorf("control server cert not anchored to our CA: %w", err)
		}
		// Trust by identity, not hostname.
		if got := spiffeID(leaf); got != expectedServerID {
			return fmt.Errorf("control server SPIFFE id %q != expected %q", got, expectedServerID)
		}
		return nil
	}

	tlsCfg := &tls.Config{
		Certificates:          []tls.Certificate{id.Cert},
		InsecureSkipVerify:    true, // replaced by VerifyPeerCertificate (pin + SPIFFE) below
		VerifyPeerCertificate: verify,
		MinVersion:            tls.VersionTLS13, // control link is ours end-to-end — 1.3 only
	}
	return &ControlClient{
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		baseURL: baseURL,
	}
}

// fetchAllowList pulls this tenant's ACTIVE node SVIDs from the tower.
func (c *ControlClient) fetchAllowList() (string, []NodeEntry, error) {
	out, err := c.call("/control/v1/allowlist", map[string]any{})
	if err != nil {
		return "", nil, err
	}
	tenant, _ := out["tenant"].(string)
	var nodes []NodeEntry
	if raw, ok := out["nodes"].([]any); ok {
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				nodes = append(nodes, NodeEntry{
					SVID:            asString(m["svid"]),
					SPKIFingerprint: asString(m["spki_fingerprint"]),
					BoundName:       asString(m["bound_name"]),
					Description:     asString(m["description"]),
					NotAfter:        asString(m["not_after"]),
				})
			}
		}
	}
	return tenant, nodes, nil
}

func asString(v any) string { s, _ := v.(string); return s }

// reportTunnels tells the tower which node tunnels are live, with each node's
// running version/arch (operator version visibility), AND ships the buffered
// audit/call events (the Witchhunt log) in the same round-trip. The tower
// replies with any operator-requested update nudges (SVIDs) for this tenant —
// the PULL side of the console "update now" button (Orthanc never dials down).
func (c *ControlClient) reportTunnels(tunnels []map[string]any, calls []callEvent) ([]string, error) {
	body := map[string]any{"tunnels": tunnels, "instance_id": c.instanceID}
	if len(calls) > 0 {
		body["calls"] = calls
	}
	out, err := c.call("/control/v1/report", body)
	if err != nil {
		return nil, err
	}
	var nudges []string
	if raw, ok := out["pending_nudges"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				nudges = append(nudges, s)
			}
		}
	}
	return nudges, nil
}

// shipCalls flushes buffered audit events to the tower's persist-only call-log
// endpoint — the low-latency path (fired ~200ms after a call) so the Witchhunt
// log feels live instead of waiting for the ~30s heartbeat. No tunnel/nudge
// side effects.
func (c *ControlClient) shipCalls(calls []callEvent) error {
	if len(calls) == 0 {
		return nil
	}
	_, err := c.call("/control/v1/calllog",
		map[string]any{"calls": calls, "instance_id": c.instanceID})
	return err
}

// updateFor asks the tower whether a node is behind its channel's target; the
// reply carries the Orthanc-signed binary (b64) when an update is due.
func (c *ControlClient) updateFor(svid, currentVersion, goos, goarch string) (map[string]any, error) {
	return c.call("/control/v1/update_for", map[string]any{
		"svid": svid, "current_version": currentVersion, "goos": goos, "goarch": goarch})
}

// signRenew relays a renewal CSR to Orthanc (purpose=renew, key-continuity);
// returns the freshly-signed cert for the same identity.
func (c *ControlClient) signRenew(csrPEM string) (map[string]any, error) {
	return c.call("/control/v1/sign", map[string]any{"purpose": "renew", "csr": csrPEM})
}

// enroll relays a node's CSR + join token up to Orthanc (purpose=enroll). The
// node has no cert yet, so this is reached via XConnect's certless /bootstrap
// door; Orthanc validates the join token and creates a PENDING enrollment.
func (c *ControlClient) enroll(csrPEM, joinToken, name string) (map[string]any, error) {
	return c.call("/control/v1/sign", map[string]any{
		"purpose": "enroll", "csr": csrPEM, "join_token": joinToken, "name": name})
}

// enrollStatus polls an enrollment; once an operator approves it, Orthanc
// returns the signed cert + trust bundle.
func (c *ControlClient) enrollStatus(enrollmentID string) (map[string]any, error) {
	return c.call("/control/v1/enroll_status", map[string]any{"enrollment_id": enrollmentID})
}

// principalBody is the identity block Orthanc uses for authZ + discovery. We send
// the immutable oid (the policy/audit key) alongside upn/name (display) and tid.
// revCount returns this tenant's monotonic count of revoked enrollments — a cheap
// signal (O(1), not the full allow-list) polled fast so a revoke kills the live
// tunnel within seconds, not a whole heartbeat. It only ever increases.
func (c *ControlClient) revCount() (int, error) {
	out, err := c.call("/control/v1/revstate", map[string]any{})
	if err != nil {
		return 0, err
	}
	n, _ := out["revoked"].(float64) // JSON numbers decode as float64
	return int(n), nil
}

func principalBody(p *principal) map[string]any {
	return map[string]any{
		"principal_upn": p.UPN, "principal_oid": p.OID, "principal_tid": p.TID,
		"principal_name": p.Name, "principal_groups": p.Groups,
		// The agent (azp). Used by the tower's agent jail in dev/no-validate mode;
		// in validate mode the tower re-derives azp from the verified token instead.
		"principal_app": p.AppID,
		// The raw OBO bearer: Orthanc re-validates it against the Entra JWKS and
		// derives the principal from the VERIFIED token, so a compromised XConnect
		// can't fabricate an identity — only relay a real, unexpired one.
		"principal_token": p.Raw,
	}
}

// whoami returns the principal's grants (debug).
func (c *ControlClient) whoami(p *principal) (map[string]any, error) {
	return c.call("/control/v1/whoami", principalBody(p))
}

// knowledgeSearch reads a node's shared knowledge ("wiki for agents") via the
// tower. Orthanc authorizes (knowledge_read) + stamps nothing (read path); the
// layered result (critical_core/node_knowledge/similar_nodes + over_budget) is
// relayed straight back to the agent. svid identifies the node.
func (c *ControlClient) knowledgeSearch(p *principal, svid, query string) (map[string]any, error) {
	body := principalBody(p)
	body["svid"] = svid
	body["query"] = query
	return c.call("/control/v1/knowledge/search", body)
}

// knowledgeAppend records one knowledge entry on a node. Orthanc authorizes
// (knowledge_write → needs `full`) and stamps provenance (author/source/time)
// from the principal — we forward the principal but never the authorship claim.
func (c *ControlClient) knowledgeAppend(p *principal, svid, content string) (map[string]any, error) {
	body := principalBody(p)
	body["svid"] = svid
	body["content"] = content
	return c.call("/control/v1/knowledge/append", body)
}

// authorize asks the tower whether an OBO principal may exercise a verb. Orthanc
// also discovers the principal off this call (upserts it for the console).
func (c *ControlClient) authorize(p *principal, verb string) (bool, string, error) {
	body := principalBody(p)
	body["verb"] = verb
	out, err := c.call("/control/v1/authorize", body)
	if err != nil {
		return false, "", err
	}
	allowed, _ := out["allowed"].(bool)
	reason, _ := out["reason"].(string)
	return allowed, reason, nil
}

func (c *ControlClient) call(method string, reqBody any) (map[string]any, error) {
	var buf bytes.Buffer
	if reqBody != nil {
		if err := json.NewEncoder(&buf).Encode(reqBody); err != nil {
			return nil, err
		}
	}
	resp, err := c.http.Post(c.baseURL+method, "application/json", &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Cap the control-link response like the data-plane read (broker.go): a
	// compromised/buggy Orthanc must not be able to OOM us with an unbounded body.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("control %s -> HTTP %d: %v", method, resp.StatusCode, out["error"])
	}
	return out, nil
}
