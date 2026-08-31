package main

import "testing"

func TestWriteMetadataRequested(t *testing.T) {
	tests := []struct {
		name string
		body map[string]any
		want bool
	}{
		{name: "ordinary-write", body: map[string]any{"path": "/tmp/a", "content": "x"}, want: false},
		{name: "empty-fields", body: map[string]any{"owner": "", "group": "  ", "mode": nil}, want: false},
		{name: "owner", body: map[string]any{"owner": "root"}, want: true},
		{name: "group", body: map[string]any{"group": "www-data"}, want: true},
		{name: "mode", body: map[string]any{"mode": "0640"}, want: true},
		{name: "wrong-type-fails-closed", body: map[string]any{"mode": 640}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := writeMetadataRequested(tc.body); got != tc.want {
				t.Fatalf("writeMetadataRequested(%#v) = %v; want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestMetadataEndpointUnsupportedDetectionShape(t *testing.T) {
	// Broker.Inject returns this exact summary shape. The caller treats a 404
	// from the additive endpoint as a capability conflict rather than success.
	if out := "HTTP 404 404 page not found\n"; !metadataEndpointUnsupported(out) {
		t.Fatalf("expected unsupported detection for %q", out)
	}
	for _, out := range []string{
		"HTTP 200 {\"ok\":true}",
		"HTTP 400 {\"error\":\"invalid mode\"}",
		"HTTP 500 {\"error\":\"write failed\"}",
	} {
		if metadataEndpointUnsupported(out) {
			t.Fatalf("unexpected unsupported detection for %q", out)
		}
	}
}
