package main

import (
	"strings"
	"testing"
)

func TestReadBoundedResponseAcceptsExactLimit(t *testing.T) {
	body, err := readBoundedResponse(strings.NewReader("1234"), 4)
	if err != nil {
		t.Fatalf("exact-limit response rejected: %v", err)
	}
	if string(body) != "1234" {
		t.Fatalf("body = %q, want exact response", body)
	}
}

func TestReadBoundedResponseRejectsRatherThanSilentlyTruncates(t *testing.T) {
	body, err := readBoundedResponse(strings.NewReader("12345"), 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected explicit oversize error, body=%q err=%v", body, err)
	}
	if body != nil {
		t.Fatalf("oversize response returned a partial body: %q", body)
	}
}
