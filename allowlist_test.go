package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
)

func TestLastNodeRevocationClosesTunnel(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http2.Transport{}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	svid := "spiffe://pow3rtool/prod/node/one"
	allow := NewAllowList()
	allow.Replace("prod", []NodeEntry{{SVID: svid, SPKIFingerprint: "key-one"}})
	broker := &Broker{allow: allow, control: testControlClient(t, `{"tenant":"prod","count":0,"nodes":[]}`)}
	broker.tunnels.Store(svid, cc)
	broker.versions.Store(svid, "v1")
	if err := broker.refreshAndReconcile(); err != nil {
		t.Fatal(err)
	}
	if _, ok := allow.Lookup("key-one"); ok {
		t.Fatal("revoked node can still pass the handshake allow-list")
	}
	if _, ok := broker.tunnels.Load(svid); ok {
		t.Fatal("revoked tunnel remains registered")
	}
	if _, ok := broker.versions.Load(svid); ok {
		t.Fatal("revoked tunnel version remains registered")
	}
	if !cc.State().Closed {
		t.Fatal("revoked HTTP/2 connection remains open")
	}
}

func TestInvalidAllowListsPreserveExistingAccessState(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"tenant":"prod","count":0}`, `{"tenant":"prod","count":0,"nodes":null}`,
		`{"tenant":"prod","count":1,"nodes":[]}`, `{"tenant":"other","count":0,"nodes":[]}`,
		`{"tenant":"prod","count":1,"nodes":[{}]}`,
		`{"tenant":"prod","count":1,"nodes":[{"svid":"spiffe://pow3rtool/other/node/x","spki_fingerprint":"key"}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			allow := NewAllowList()
			allow.Replace("prod", []NodeEntry{{SVID: "spiffe://pow3rtool/prod/node/one", SPKIFingerprint: "key-one"}})
			control := testControlClient(t, body)
			control.expectedTenant = "prod"
			broker := &Broker{allow: allow, control: control}
			if err := broker.refreshAndReconcile(); err == nil {
				t.Fatal("malformed or wrong-tenant snapshot accepted")
			}
			if _, ok := allow.Lookup("key-one"); !ok {
				t.Fatal("invalid response removed existing state")
			}
		})
	}
}

func TestAllowListOutagePreservesExistingState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	allow := NewAllowList()
	allow.Replace("prod", []NodeEntry{{SVID: "spiffe://pow3rtool/prod/node/one", SPKIFingerprint: "key-one"}})
	broker := &Broker{allow: allow, control: &ControlClient{http: server.Client(), baseURL: server.URL}}
	if err := broker.refreshAndReconcile(); err == nil {
		t.Fatal("failed control request accepted")
	}
	if _, ok := allow.Lookup("key-one"); !ok {
		t.Fatal("outage removed previous state")
	}
}
