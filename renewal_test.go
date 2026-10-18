package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const renewalTestSVID = "spiffe://pow3rtool/prod/node/renewal-test"

type renewalFixture struct {
	broker      *Broker
	csrCalls    atomic.Int32
	signCalls   atomic.Int32
	applyCalls  atomic.Int32
	applyStatus int
	applyBody   string
	csrEntered  chan struct{}
	csrRelease  chan struct{}
}

func newRenewalFixture(t *testing.T, remaining, window time.Duration) *renewalFixture {
	t.Helper()
	f := &renewalFixture{applyStatus: http.StatusOK, applyBody: `{"applied":true,"not_after":"2030-01-01T00:00:00Z"}`}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control/v1/sign" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["purpose"] != "renew" || body["csr"] != "test-csr" {
			t.Errorf("unexpected signing request: %v", body)
		}
		f.signCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"certificate":"test-certificate"}`))
	}))
	t.Cleanup(control.Close)
	node := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/renew/csr":
			f.csrCalls.Add(1)
			if f.csrEntered != nil {
				select {
				case f.csrEntered <- struct{}{}:
				default:
				}
				<-f.csrRelease
			}
			_, _ = w.Write([]byte(`{"csr":"test-csr"}`))
		case "/renew/apply":
			f.applyCalls.Add(1)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["certificate"] != "test-certificate" {
				t.Errorf("unexpected certificate apply: %v", body)
			}
			w.WriteHeader(f.applyStatus)
			_, _ = w.Write([]byte(f.applyBody))
		default:
			http.NotFound(w, r)
		}
	}))
	node.EnableHTTP2 = true
	node.StartTLS()
	t.Cleanup(node.Close)
	conn, err := tls.Dial("tcp", node.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	allow := NewAllowList()
	allow.Replace("prod", []NodeEntry{{SVID: renewalTestSVID, SPKIFingerprint: "test-key", NotAfter: time.Now().Add(remaining).Format(time.RFC3339)}})
	f.broker = &Broker{allow: allow, renewBefore: window, control: &ControlClient{http: control.Client(), baseURL: control.URL}}
	f.broker.tunnels.Store(renewalTestSVID, cc)
	return f
}

func TestRenewalScheduleAndMigration(t *testing.T) {
	for _, tc := range []struct {
		name              string
		remaining, window time.Duration
		want              int32
	}{
		{"fresh thirty-day certificate", 30 * 24 * time.Hour, 23 * 24 * time.Hour, 0},
		{"before weekly renewal", 23*24*time.Hour + time.Hour, 23 * 24 * time.Hour, 0},
		{"weekly renewal due", 23*24*time.Hour - time.Hour, 23 * 24 * time.Hour, 1},
		{"old seven-day certificate migrates immediately", 7 * 24 * time.Hour, 23 * 24 * time.Hour, 1},
		{"safe default skips fresh seven-day certificate", 7 * 24 * time.Hour, 0, 0},
		{"safe default renews near expiry", 24 * time.Hour, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenewalFixture(t, tc.remaining, tc.window)
			f.broker.renewIfDue(renewalTestSVID)
			f.broker.renewIfDue(renewalTestSVID) // stale allow-list after a reconnect
			if f.signCalls.Load() != tc.want || f.applyCalls.Load() != tc.want {
				t.Fatalf("sign/apply=%d/%d, want %d each", f.signCalls.Load(), f.applyCalls.Load(), tc.want)
			}
			// Once the issuer's refreshed expiry arrives, the new leaf stays quiet.
			f.broker.allow.Replace("prod", []NodeEntry{{SVID: renewalTestSVID, SPKIFingerprint: "test-key", NotAfter: time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)}})
			f.broker.renewIfDue(renewalTestSVID)
			if f.signCalls.Load() != tc.want {
				t.Fatal("freshly renewed certificate was renewed again")
			}
		})
	}
}

func TestRejectedCertificateApplicationCanRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"remote error", http.StatusBadRequest, `{"error":"invalid certificate"}`},
		{"not applied", http.StatusOK, `{"applied":false}`},
		{"invalid response", http.StatusOK, `not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenewalFixture(t, 24*time.Hour, 48*time.Hour)
			f.applyStatus, f.applyBody = tc.status, tc.body
			f.broker.renewIfDue(renewalTestSVID)
			f.broker.renewIfDue(renewalTestSVID)
			if f.applyCalls.Load() != 2 {
				t.Fatal("failed renewal incorrectly suppressed retry")
			}
		})
	}
}

func TestConcurrentRenewalTriggersIssueOneCertificate(t *testing.T) {
	f := newRenewalFixture(t, 24*time.Hour, 48*time.Hour)
	f.csrEntered = make(chan struct{}, 1)
	f.csrRelease = make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(f.csrRelease) }) })
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); f.broker.renewIfDue(renewalTestSVID) }()
	select {
	case <-f.csrEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("CSR request never started")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.broker.renewIfDue(renewalTestSVID) }()
	}
	otherDone := make(chan struct{})
	go func() { wg.Wait(); close(otherDone) }()
	select {
	case <-otherDone:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent triggers did not return while renewal was in flight")
	}
	release.Do(func() { close(f.csrRelease) })
	select {
	case <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("renewal did not finish")
	}
	if f.csrCalls.Load() != 1 || f.signCalls.Load() != 1 || f.applyCalls.Load() != 1 {
		t.Fatalf("duplicate renewal: CSR/sign/apply=%d/%d/%d", f.csrCalls.Load(), f.signCalls.Load(), f.applyCalls.Load())
	}
}
