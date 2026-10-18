package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
)

// callEvent is one audited fabric call as XConnect sees it — the only point
// with the WHOLE picture (validated principal + Orthanc's authZ decision +
// resolved target + injection outcome). Shipped batched to Orthanc on the
// heartbeat, where it becomes a row in the Witchhunt log. JSON tags match what
// the tower's report handler reads.
type callEvent struct {
	// Phase distinguishes the two shipments of one call. "" (omitted) is the
	// terminal event — a finished call → an append-only CallEvent in the tower.
	// "start" is the in-flight marker, emitted the moment we inject an
	// authorized+resolved call → a transient "running" row, cleared by the
	// terminal event carrying the same RequestID.
	Phase string `json:"phase,omitempty"`
	// RequestID correlates the start and terminal shipments of one call, and is
	// the tower's idempotency key (a re-shipped batch can't double-write).
	RequestID string `json:"rid,omitempty"`

	TS      string `json:"ts"`      // RFC3339, when the call arrived (XConnect-stamped)
	UPN     string `json:"upn"`     // OBO principal
	OID     string `json:"oid"`     // durable audit key
	TID     string `json:"tid"`     // tenant id of the principal
	App     string `json:"app,omitempty"`      // agent: OAuth client app id (azp/appid)
	AppName string `json:"app_name,omitempty"` // agent: app display name (when present)
	Verb    string `json:"verb"`    // verb class (run/full/read/knowledge_*)
	Node    string `json:"node"`    // target as the caller asked (name/fragment)
	SVID    string `json:"svid"`    // resolved target SVID (empty if unresolved)
	Allowed bool   `json:"allowed"` // the perimeter decision
	Reason  string `json:"reason"`  // authZ reason
	Status  string `json:"status"`  // ok|denied|no-tunnel|ambiguous|error:…
	Detail  string `json:"detail"`  // bounded command/path summary

	// Result capture — what the call actually DID, so an operator can drill in.
	// Populated only for calls that reached a node (the Inject response).
	HTTPStatus int    `json:"http_status,omitempty"`     // RCON's HTTP code
	RC         *int   `json:"rc,omitempty"`              // process exit code, when the verb reports one
	DurMs      int    `json:"dur_ms,omitempty"`          // node-side duration
	Output     string `json:"output,omitempty"`         // bounded response body (stdout/stderr/etc.)
	Truncated  bool   `json:"output_truncated,omitempty"` // output exceeded the audit cap
}

// auditOutputCap bounds how much per-call output we retain centrally. RCON caps
// a run at 1 MB; we keep the first 64 KB for the audit trail (flagged when more
// was produced). Tunable if richer forensics are wanted vs DB footprint.
const auditOutputCap = 64 << 10

// captureResult parses an Inject summary ("HTTP <code> <body>") into the event:
// the HTTP status, a bounded copy of the body, and (best-effort) the rc/dur that
// the run/jobs verbs report inside that body.
func (e *callEvent) captureResult(injectOut string) {
	body := injectOut
	if strings.HasPrefix(injectOut, "HTTP ") {
		rest := injectOut[len("HTTP "):]
		if sp := strings.IndexByte(rest, ' '); sp >= 0 {
			if code, err := strconv.Atoi(rest[:sp]); err == nil {
				e.HTTPStatus = code
				body = rest[sp+1:]
			}
		}
	}
	if len(body) > auditOutputCap {
		e.Output = body[:auditOutputCap]
		e.Truncated = true
	} else {
		e.Output = body
	}
	// Best-effort: pull rc + dur out of the run/jobs JSON shape.
	var r struct {
		RC  *int     `json:"rc"`
		Dur *float64 `json:"dur"`
	}
	if i := strings.IndexByte(body, '{'); i >= 0 {
		if json.Unmarshal([]byte(body[i:]), &r) == nil {
			e.RC = r.RC
			if r.Dur != nil {
				e.DurMs = int(*r.Dur * 1000)
			}
		}
	}
}

// CallLog is an in-memory ring of recent call events awaiting the next
// heartbeat ship. Bounded: if Orthanc is unreachable and events pile up, the
// OLDEST are dropped (liveness over completeness — the buffer can't grow
// without bound and starve the box). A drop is logged by the caller.
type CallLog struct {
	mu     sync.Mutex
	buf    []callEvent
	max    int
	notify chan struct{} // size-1; pinged on Add so the shipper flushes fast
}

func NewCallLog(max int) *CallLog {
	if max <= 0 {
		max = 2000
	}
	return &CallLog{max: max, notify: make(chan struct{}, 1)}
}

// Add appends an event, dropping the oldest if the buffer is full, then nudges
// the shipper (non-blocking — a coalesced flush picks up bursts).
func (c *CallLog) Add(e callEvent) {
	c.mu.Lock()
	if len(c.buf) >= c.max {
		// Drop oldest to make room (keep the most recent window).
		copy(c.buf, c.buf[1:])
		c.buf = c.buf[:len(c.buf)-1]
	}
	c.buf = append(c.buf, e)
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default: // already signalled; the shipper will drain everything
	}
}

// Notify is the channel the shipper waits on for new events.
func (c *CallLog) Notify() <-chan struct{} { return c.notify }

// Drain returns all buffered events and clears the buffer. The caller ships
// them; if the ship fails it can Requeue so nothing is lost on a transient
// control-link blip.
func (c *CallLog) Drain() []callEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) == 0 {
		return nil
	}
	out := c.buf
	c.buf = nil
	return out
}

// Requeue puts drained events back at the FRONT after a failed ship, capped to
// max (oldest dropped) so a long Orthanc outage can't make the buffer unbounded.
func (c *CallLog) Requeue(evs []callEvent) {
	if len(evs) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	merged := append(evs, c.buf...)
	if len(merged) > c.max {
		merged = merged[len(merged)-c.max:]
	}
	c.buf = merged
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// newID mints a 128-bit random id (hex). Used for the per-call RequestID (ties a
// call's start↔terminal events, and is the tower's idempotency key) and for the
// per-process instanceID (the restart-corrective: a new process => a new id, so
// the tower can clear the old process's still-"running" rows).
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
