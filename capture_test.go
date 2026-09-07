package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCaptureConfig() captureStoreConfig {
	return captureStoreConfig{
		TTL:                10 * time.Minute,
		MaxEntries:         8,
		MaxBytes:           1 << 20,
		MaxOwnerEntries:    3,
		MaxOwnerBytes:      1 << 19,
		MaxIndividualBytes: 1 << 18,
	}
}

func TestCaptureOwnerIncludesTenantHumanAndAgent(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newCaptureStore(testCaptureConfig(), func() time.Time { return now })
	owner := captureOwner{TID: "tenant-a", OID: "human-a", AppID: "agent-a"}
	capture, err := store.Put(
		owner,
		"spiffe://tenant-a/node/one",
		"run",
		"request-one",
		map[string]string{"stdout": "hello", "stderr": ""},
		false,
	)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !validCaptureID(capture.ID) {
		t.Fatalf("capture id %q is not a 128-bit opaque id", capture.ID)
	}
	if got, ok := store.Get(capture.ID, owner); !ok || got.ID != capture.ID {
		t.Fatalf("owner could not retrieve capture")
	}
	for _, other := range []captureOwner{
		{TID: "tenant-b", OID: owner.OID, AppID: owner.AppID},
		{TID: owner.TID, OID: "human-b", AppID: owner.AppID},
		{TID: owner.TID, OID: owner.OID, AppID: "agent-b"},
	} {
		if _, ok := store.Get(capture.ID, other); ok {
			t.Fatalf("capture leaked to owner %#v", other)
		}
	}
}

func TestCaptureExpiresAndIsRemoved(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newCaptureStore(testCaptureConfig(), func() time.Time { return now })
	owner := captureOwner{TID: "tenant", OID: "human", AppID: "agent"}
	capture, err := store.Put(
		owner, "node", "run", "request",
		map[string]string{"stdout": "secret", "stderr": ""},
		false,
	)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	now = now.Add(10 * time.Minute)
	if _, ok := store.Get(capture.ID, owner); ok {
		t.Fatalf("expired capture remained readable")
	}
	if len(store.captures) != 0 || store.bytes != 0 {
		t.Fatalf("expired capture was not removed from memory")
	}
}

func TestCaptureOwnerQuotaEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	config := testCaptureConfig()
	config.MaxOwnerEntries = 2
	store := newCaptureStore(config, func() time.Time { return now })
	owner := captureOwner{TID: "tenant", OID: "human", AppID: "agent"}

	first, _ := store.Put(owner, "node", "run", "one", map[string]string{"stdout": "one"}, false)
	now = now.Add(time.Second)
	second, _ := store.Put(owner, "node", "run", "two", map[string]string{"stdout": "two"}, false)
	now = now.Add(time.Second)
	if _, ok := store.Get(first.ID, owner); !ok {
		t.Fatal("first capture unexpectedly missing before eviction")
	}
	now = now.Add(time.Second)
	third, err := store.Put(owner, "node", "run", "three", map[string]string{"stdout": "three"}, false)
	if err != nil {
		t.Fatalf("third Put: %v", err)
	}
	if _, ok := store.Get(second.ID, owner); ok {
		t.Fatal("least recently used capture was not evicted")
	}
	if _, ok := store.Get(first.ID, owner); !ok {
		t.Fatal("recently accessed capture was evicted")
	}
	if _, ok := store.Get(third.ID, owner); !ok {
		t.Fatal("new capture was not retained")
	}
}

func TestCaptureRejectsOversizeIndividualOutput(t *testing.T) {
	now := time.Now()
	config := testCaptureConfig()
	config.MaxIndividualBytes = 4
	store := newCaptureStore(config, func() time.Time { return now })
	owner := captureOwner{TID: "tenant", OID: "human", AppID: "agent"}

	_, err := store.Put(owner, "node", "run", "request", map[string]string{"stdout": "12345"}, false)
	if err == nil || !strings.Contains(err.Error(), "capture limit") {
		t.Fatalf("expected individual capture limit error, got %v", err)
	}
}

func TestReadCapturedOutputPagesUnicodeByCharacter(t *testing.T) {
	capture := &capturedOutput{
		ID:        "cap_0123456789abcdef0123456789abcdef",
		Streams:   map[string]string{"stdout": "abc😀def"},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	page, err := readCapturedOutput(capture, outputReadRequest{
		Stream: "stdout", Mode: "page", Offset: 3, Limit: 1,
	})
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if page["content"] != "😀" || page["next_offset"] != 4 {
		t.Fatalf("unexpected unicode page: %#v", page)
	}
	tail, err := readCapturedOutput(capture, outputReadRequest{
		Stream: "stdout", Mode: "tail", Limit: 3,
	})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if tail["content"] != "def" || tail["eof"] != true {
		t.Fatalf("unexpected tail: %#v", tail)
	}
}

func TestSearchCapturedOutputIsBoundedAndResumable(t *testing.T) {
	capture := &capturedOutput{
		ID: "cap_0123456789abcdef0123456789abcdef",
		Streams: map[string]string{
			"stderr": "start\nERROR one\nmiddle\nERROR two\nend\n",
		},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	result, err := readCapturedOutput(capture, outputReadRequest{
		Stream: "stderr", Mode: "search", Pattern: "^ERROR",
		Context: 1, Limit: 64_000, MaxMatches: 1,
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	matches := result["match_lines"].([]int)
	if len(matches) != 1 || matches[0] != 2 {
		t.Fatalf("unexpected matches: %#v", matches)
	}
	if result["next_start_line"] != 2 || result["eof"] != false {
		t.Fatalf("search cursor is not resumable: %#v", result)
	}
	if !strings.Contains(result["content"].(string), "2:ERROR one") {
		t.Fatalf("search omitted matching line: %#v", result)
	}
	complete, err := readCapturedOutput(capture, outputReadRequest{
		Stream: "stderr", Mode: "search", Pattern: "^ERROR",
		Context: 1, Limit: 64_000, MaxMatches: 10,
	})
	if err != nil {
		t.Fatalf("complete search: %v", err)
	}
	if complete["next_start_line"] != 5 || complete["eof"] != true || complete["content_truncated"] != false {
		t.Fatalf("completed search did not report EOF: %#v", complete)
	}

	_, err = readCapturedOutput(capture, outputReadRequest{
		Stream: "stderr", Mode: "search", Pattern: "[", Limit: 100,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid RE2") {
		t.Fatalf("expected bounded regex validation error, got %v", err)
	}
}

func TestPrepareRunResultAutoCapturesLargeOutput(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newCaptureStore(defaultCaptureStoreConfig(), func() time.Time { return now })
	caller := &Caller{captures: store}
	principal := &principal{TID: "tenant", OID: "human", AppID: "agent"}
	stdout := strings.Repeat("x", captureInlineThreshold+1)
	body, _ := json.Marshal(map[string]any{
		"rc": 0, "stdout": stdout, "stderr": "", "truncated": false,
	})

	summary, err := caller.prepareRunResult(
		principal, "node", "run", "request", injectResult{StatusCode: 200, Body: body}, false,
	)
	if err != nil {
		t.Fatalf("prepareRunResult: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(summary, "HTTP 200 ")), &result); err != nil {
		t.Fatalf("decode prepared response: %v", err)
	}
	if result["output_captured"] != true {
		t.Fatalf("large output was not captured: %#v", result)
	}
	if got := len([]rune(result["stdout"].(string))); got != capturePreviewChars {
		t.Fatalf("stdout preview is %d chars, want %d", got, capturePreviewChars)
	}
	descriptor := result["output_capture"].(map[string]any)
	captureID := descriptor["capture_id"].(string)
	captured, ok := store.Get(captureID, captureOwner{TID: "tenant", OID: "human", AppID: "agent"})
	if !ok || captured.Streams["stdout"] != stdout {
		t.Fatal("capture store did not retain the complete output")
	}
}

func TestPrepareRunResultLeavesSmallOutputInlineUnlessForced(t *testing.T) {
	now := time.Now()
	store := newCaptureStore(defaultCaptureStoreConfig(), func() time.Time { return now })
	caller := &Caller{captures: store}
	principal := &principal{TID: "tenant", OID: "human", AppID: "agent"}
	body := []byte("{\"rc\":0,\"stdout\":\"small\",\"stderr\":\"\"}")
	response := injectResult{StatusCode: 200, Body: body}

	inline, err := caller.prepareRunResult(principal, "node", "run", "request", response, false)
	if err != nil {
		t.Fatalf("inline: %v", err)
	}
	if inline != response.Summary() || len(store.captures) != 0 {
		t.Fatal("small output was unexpectedly captured")
	}
	forced, err := caller.prepareRunResult(principal, "node", "run", "request", response, true)
	if err != nil {
		t.Fatalf("forced: %v", err)
	}
	if forced == response.Summary() || len(store.captures) != 1 {
		t.Fatal("capture=true did not force a capture")
	}
}

func TestOutputReadHandlerReauthorizesOriginalVerb(t *testing.T) {
	store := newCaptureStore(defaultCaptureStoreConfig(), time.Now)
	owner := captureOwner{TID: "tenant", OID: "human", AppID: "agent"}
	capture, err := store.Put(
		owner, "spiffe://tenant/node/one", "run", "source-request",
		map[string]string{"stdout": "sensitive", "stderr": ""}, false,
	)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	authCalls := 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCalls++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["verb"] != "run" {
			t.Errorf("authorize verb = %v, want run", body["verb"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"allowed\":false,\"reason\":\"revoked\"}"))
	}))
	defer control.Close()

	caller := &Caller{
		captures: store,
		control:  &ControlClient{http: control.Client(), baseURL: control.URL},
		validate: func(string) (*principal, error) {
			return &principal{TID: owner.TID, OID: owner.OID, AppID: owner.AppID, UPN: "user"}, nil
		},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/output/read",
		strings.NewReader("{\"capture_id\":\""+capture.ID+"\",\"stream\":\"stdout\"}"),
	)
	request.Header.Set("Authorization", "Bearer test")
	response := httptest.NewRecorder()

	caller.outputReadHandler(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", response.Code, response.Body.String())
	}
	if authCalls != 1 {
		t.Fatalf("authorization was called %d times, want 1", authCalls)
	}
	if strings.Contains(response.Body.String(), "sensitive") {
		t.Fatal("denied response leaked captured output")
	}
}

func TestOutputReadAuditNeverCopiesReturnedChunk(t *testing.T) {
	store := newCaptureStore(defaultCaptureStoreConfig(), time.Now)
	owner := captureOwner{TID: "tenant", OID: "human", AppID: "agent"}
	capture, err := store.Put(
		owner, "spiffe://tenant/node/one", "run", "source-request",
		map[string]string{"stdout": "sensitive-capture-content", "stderr": ""}, false,
	)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"allowed\":true,\"reason\":\"test grant\"}"))
	}))
	defer control.Close()
	calls := NewCallLog(10)
	caller := &Caller{
		captures: store,
		calls:    calls,
		control:  &ControlClient{http: control.Client(), baseURL: control.URL},
		validate: func(string) (*principal, error) {
			return &principal{TID: owner.TID, OID: owner.OID, AppID: owner.AppID, UPN: "user"}, nil
		},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/output/read",
		strings.NewReader("{\"capture_id\":\""+capture.ID+"\",\"stream\":\"stdout\",\"limit\":100}"),
	)
	request.Header.Set("Authorization", "Bearer test")
	response := httptest.NewRecorder()

	caller.outputReadHandler(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "sensitive-capture-content") {
		t.Fatalf("authorized read failed: status=%d body=%s", response.Code, response.Body.String())
	}
	events := calls.Drain()
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	event := events[0]
	if event.Output != "" || event.Truncated {
		t.Fatalf("capture read copied output into audit: %#v", event)
	}
	if strings.Contains(event.Detail, capture.ID) {
		t.Fatalf("capture locator was persisted in audit detail: %q", event.Detail)
	}
}
