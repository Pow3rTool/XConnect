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
// Successful empty snapshots are authoritative; failed fetches never replace state.
type AllowList struct {
	mu      sync.RWMutex
	bySPKI  map[string]NodeEntry
	tenant  string
	updated time.Time
	loaded  bool // has an authoritative snapshot ever been applied?
}

func NewAllowList() *AllowList {
	return &AllowList{bySPKI: map[string]NodeEntry{}}
}

// Replace applies a validated snapshot, including an authoritative empty list.
// A failed or malformed fetch never calls Replace. Tenant changes are rejected.
func (a *AllowList) Replace(tenant string, nodes []NodeEntry) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if tenant == "" || (a.loaded && tenant != a.tenant) {
		return false
	}
	m := make(map[string]NodeEntry, len(nodes))
	for _, n := range nodes {
		m[n.SPKIFingerprint] = n
	}
	a.bySPKI = m
	a.tenant = tenant
	a.updated = time.Now()
	a.loaded = true
	return true
}

// Loaded reports whether an authoritative snapshot has ever been applied — reconcile
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
