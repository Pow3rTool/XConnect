package main

import (
	"sync"
	"time"
)

// NodeEntry is one approved node as the tower reports it.
type NodeEntry struct {
	SVID            string
	SPKIFingerprint string
	BoundName       string
	Description     string
	NotAfter        string // RFC3339 cert expiry (for renewal scheduling)
}

// AllowList is XConnect's cached, tenant-scoped view of which nodes may connect.
// Refreshed from the control link; the broker consults it on every handshake.
// Resilience: an EMPTY snapshot is never applied once real data has loaded — it's
// retained as last-known-good (see Replace).
type AllowList struct {
	mu      sync.RWMutex
	bySPKI  map[string]NodeEntry
	tenant  string
	updated time.Time
	loaded  bool // has a non-empty snapshot ever been applied? (cold-start guard)
}

func NewAllowList() *AllowList {
	return &AllowList{bySPKI: map[string]NodeEntry{}}
}

// Replace swaps in a new snapshot and reports whether it was applied. An EMPTY
// snapshot is REJECTED once real data has loaded (retain last-known-good): an
// empty allow-list is far likelier a transient control-plane glitch or a forged
// response than a genuine "every node in the tenant is revoked," and applying it
// would blind enforcement / strand the fleet. Single revokes still take effect
// (they yield a non-empty list, against which reconcile drops the missing node);
// a true revoke-all is an out-of-band action. Returns false if empty was ignored.
func (a *AllowList) Replace(tenant string, nodes []NodeEntry) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(nodes) == 0 && a.loaded {
		return false // keep last-known-good
	}
	m := make(map[string]NodeEntry, len(nodes))
	for _, n := range nodes {
		m[n.SPKIFingerprint] = n
	}
	a.bySPKI = m
	a.tenant = tenant
	a.updated = time.Now()
	if len(nodes) > 0 {
		a.loaded = true
	}
	return true
}

// Loaded reports whether a non-empty snapshot has ever been applied — reconcile
// uses it to avoid dropping tunnels on a cold start (before the first fetch).
func (a *AllowList) Loaded() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.loaded
}

func (a *AllowList) Lookup(spki string) (NodeEntry, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	e, ok := a.bySPKI[spki]
	return e, ok
}

// Entries returns a snapshot of all known node entries (for SVID↔name mapping).
func (a *AllowList) Entries() []NodeEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]NodeEntry, 0, len(a.bySPKI))
	for _, e := range a.bySPKI {
		out = append(out, e)
	}
	return out
}

func (a *AllowList) Tenant() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.tenant
}

func (a *AllowList) Size() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.bySPKI)
}
