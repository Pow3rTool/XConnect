package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testControlClient(t *testing.T, body string) *ControlClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return &ControlClient{http: srv.Client(), baseURL: srv.URL}
}

func TestControlCallRejectsOversizeDefaultResponse(t *testing.T) {
	body := `{"payload":"` + strings.Repeat("x", int(controlResponseLimit)) + `"}`
	_, err := testControlClient(t, body).call("/control/v1/report", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("expected explicit response-limit error, got %v", err)
	}
}

func TestUpdateForAcceptsReleaseSizedResponse(t *testing.T) {
	const payloadSize = 10 << 20
	body := `{"update":true,"binary_b64":"` + strings.Repeat("A", payloadSize) + `"}`
	out, err := testControlClient(t, body).updateFor("node", "v0.3.3", "linux", "amd64")
	if err != nil {
		t.Fatalf("release-sized update response was rejected: %v", err)
	}
	if got := len(out["binary_b64"].(string)); got != payloadSize {
		t.Fatalf("binary payload length = %d, want %d", got, payloadSize)
	}
}

func TestControlCallRejectsInvalidJSON(t *testing.T) {
	_, err := testControlClient(t, `{"ok":`).call("/control/v1/report", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON response") {
		t.Fatalf("expected JSON decode error, got %v", err)
	}
}
