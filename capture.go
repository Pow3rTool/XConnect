package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	captureTTL                = 10 * time.Minute
	captureInlineThreshold    = 32 << 10
	capturePreviewChars       = 2048
	captureMaxEntries         = 128
	captureMaxBytes           = 64 << 20
	captureMaxOwnerEntries    = 16
	captureMaxOwnerBytes      = 16 << 20
	captureMaxIndividualBytes = 4 << 20
	captureReadDefaultChars   = 12_000
	captureReadMaxChars       = 64_000
	captureSearchMaxPattern   = 256
	captureSearchMaxContext   = 10
	captureSearchMaxMatches   = 100
)

var errCaptureNotFound = errors.New("capture not found or expired")

type captureOwner struct {
	TID   string
	OID   string
	AppID string
}

func captureOwnerFor(p *principal) (captureOwner, bool) {
	if p == nil || p.TID == "" || p.OID == "" || p.AppID == "" {
		return captureOwner{}, false
	}
	return captureOwner{TID: p.TID, OID: p.OID, AppID: p.AppID}, true
}

type capturedOutput struct {
	ID              string
	Owner           captureOwner
	Node            string
	Verb            string
	RequestID       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastAccess      time.Time
	Streams         map[string]string
	SourceTruncated bool
	Bytes           int
}

type captureStoreConfig struct {
	TTL                time.Duration
	MaxEntries         int
	MaxBytes           int
	MaxOwnerEntries    int
	MaxOwnerBytes      int
	MaxIndividualBytes int
}

type CaptureStore struct {
	mu       sync.Mutex
	captures map[string]*capturedOutput
	bytes    int
	config   captureStoreConfig
	now      func() time.Time
}

func defaultCaptureStoreConfig() captureStoreConfig {
	return captureStoreConfig{
		TTL:                captureTTL,
		MaxEntries:         captureMaxEntries,
		MaxBytes:           captureMaxBytes,
		MaxOwnerEntries:    captureMaxOwnerEntries,
		MaxOwnerBytes:      captureMaxOwnerBytes,
		MaxIndividualBytes: captureMaxIndividualBytes,
	}
}

func newCaptureStore(config captureStoreConfig, now func() time.Time) *CaptureStore {
	if now == nil {
		now = time.Now
	}
	return &CaptureStore{
		captures: make(map[string]*capturedOutput),
		config:   config,
		now:      now,
	}
}

func NewCaptureStore() *CaptureStore {
	store := newCaptureStore(defaultCaptureStoreConfig(), time.Now)
	go store.reapLoop()
	return store
}

func (s *CaptureStore) reapLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		s.reapExpiredLocked(s.now())
		s.mu.Unlock()
	}
}

func mintCaptureID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate capture id: %w", err)
	}
	return "cap_" + hex.EncodeToString(raw[:]), nil
}

func validCaptureID(id string) bool {
	if len(id) != 36 || !strings.HasPrefix(id, "cap_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}

func (s *CaptureStore) Put(
	owner captureOwner,
	node string,
	verb string,
	requestID string,
	streams map[string]string,
	sourceTruncated bool,
) (*capturedOutput, error) {
	size := 0
	copied := make(map[string]string, len(streams))
	for name, content := range streams {
		if name != "stdout" && name != "stderr" {
			return nil, fmt.Errorf("unsupported capture stream %q", name)
		}
		copied[name] = content
		size += len(content)
	}
	if s == nil {
		return nil, errors.New("capture store unavailable")
	}
	if owner.TID == "" || owner.OID == "" || owner.AppID == "" {
		return nil, errors.New("capture requires tenant, principal, and agent identities")
	}
	if size > s.config.MaxIndividualBytes {
		return nil, fmt.Errorf("output is %d bytes; capture limit is %d", size, s.config.MaxIndividualBytes)
	}
	if size > s.config.MaxOwnerBytes || size > s.config.MaxBytes {
		return nil, errors.New("output exceeds capture store quota")
	}

	id, err := mintCaptureID()
	if err != nil {
		return nil, err
	}
	now := s.now()
	capture := &capturedOutput{
		ID: id, Owner: owner, Node: node, Verb: verb, RequestID: requestID,
		CreatedAt: now, ExpiresAt: now.Add(s.config.TTL), LastAccess: now,
		Streams: copied, SourceTruncated: sourceTruncated, Bytes: size,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapExpiredLocked(now)

	for s.ownerCountLocked(owner) >= s.config.MaxOwnerEntries ||
		s.ownerBytesLocked(owner)+size > s.config.MaxOwnerBytes {
		if !s.evictOldestLocked(func(candidate *capturedOutput) bool {
			return candidate.Owner == owner
		}) {
			return nil, errors.New("owner capture quota unavailable")
		}
	}
	for len(s.captures) >= s.config.MaxEntries || s.bytes+size > s.config.MaxBytes {
		if !s.evictOldestLocked(nil) {
			return nil, errors.New("capture store quota unavailable")
		}
	}
	for s.captures[id] != nil {
		id, err = mintCaptureID()
		if err != nil {
			return nil, err
		}
		capture.ID = id
	}
	s.captures[id] = capture
	s.bytes += size
	return capture, nil
}

func (s *CaptureStore) Get(id string, owner captureOwner) (*capturedOutput, bool) {
	if s == nil || !validCaptureID(id) {
		return nil, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapExpiredLocked(now)
	capture, ok := s.captures[id]
	if !ok || capture.Owner != owner {
		return nil, false
	}
	capture.LastAccess = now
	return capture, true
}

func (s *CaptureStore) reapExpiredLocked(now time.Time) {
	for id, capture := range s.captures {
		if !now.Before(capture.ExpiresAt) {
			s.removeLocked(id)
		}
	}
}

func (s *CaptureStore) ownerCountLocked(owner captureOwner) int {
	count := 0
	for _, capture := range s.captures {
		if capture.Owner == owner {
			count++
		}
	}
	return count
}

func (s *CaptureStore) ownerBytesLocked(owner captureOwner) int {
	size := 0
	for _, capture := range s.captures {
		if capture.Owner == owner {
			size += capture.Bytes
		}
	}
	return size
}

func (s *CaptureStore) evictOldestLocked(match func(*capturedOutput) bool) bool {
	var oldest *capturedOutput
	for _, candidate := range s.captures {
		if match != nil && !match(candidate) {
			continue
		}
		if oldest == nil || candidate.LastAccess.Before(oldest.LastAccess) ||
			(candidate.LastAccess.Equal(oldest.LastAccess) &&
				candidate.CreatedAt.Before(oldest.CreatedAt)) {
			oldest = candidate
		}
	}
	if oldest == nil {
		return false
	}
	s.removeLocked(oldest.ID)
	return true
}

func (s *CaptureStore) removeLocked(id string) {
	if capture := s.captures[id]; capture != nil {
		s.bytes -= capture.Bytes
		delete(s.captures, id)
	}
}

func outputLineCount(value string) int {
	if value == "" {
		return 0
	}
	lines := strings.Count(value, "\n")
	if !strings.HasSuffix(value, "\n") {
		lines++
	}
	return lines
}

func prefixRunes(value string, limit int) (string, bool) {
	runes := []rune(value)
	if len(runes) <= limit {
		return value, false
	}
	return string(runes[:limit]), true
}

func (capture *capturedOutput) descriptor() map[string]any {
	names := make([]string, 0, len(capture.Streams))
	metadata := make(map[string]any, len(capture.Streams))
	for name, content := range capture.Streams {
		names = append(names, name)
		sum := sha256.Sum256([]byte(content))
		_, previewTruncated := prefixRunes(content, capturePreviewChars)
		metadata[name] = map[string]any{
			"bytes":             len(content),
			"chars":             utf8.RuneCountInString(content),
			"lines":             outputLineCount(content),
			"sha256":            hex.EncodeToString(sum[:]),
			"preview_truncated": previewTruncated,
		}
	}
	sort.Strings(names)
	return map[string]any{
		"captured":          true,
		"capture_id":        capture.ID,
		"reader_tool":       "read_command_output",
		"available_streams": names,
		"streams":           metadata,
		"total_bytes":       capture.Bytes,
		"created_at":        capture.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":        capture.ExpiresAt.UTC().Format(time.RFC3339),
		"source_truncated":  capture.SourceTruncated,
		"ephemeral":         true,
	}
}

func (cl *Caller) prepareRunResult(
	principal *principal,
	node string,
	verb string,
	requestID string,
	response injectResult,
	forceCapture bool,
) (string, error) {
	summary := response.Summary()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return summary, nil
	}

	var payload map[string]any
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		return summary, nil
	}
	stdout, stdoutOK := payload["stdout"].(string)
	stderr, stderrOK := payload["stderr"].(string)
	if !stdoutOK && !stderrOK {
		return summary, nil
	}
	if !forceCapture && len(stdout)+len(stderr) <= captureInlineThreshold {
		return summary, nil
	}
	owner, ok := captureOwnerFor(principal)
	if !ok {
		return "", errors.New("validated identity lacks tenant, principal, or agent id required for capture")
	}
	sourceTruncated, _ := payload["truncated"].(bool)
	capture, err := cl.captures.Put(
		owner,
		node,
		verb,
		requestID,
		map[string]string{"stdout": stdout, "stderr": stderr},
		sourceTruncated,
	)
	if err != nil {
		return "", err
	}
	stdoutPreview, _ := prefixRunes(stdout, capturePreviewChars)
	stderrPreview, _ := prefixRunes(stderr, capturePreviewChars)
	payload["stdout"] = stdoutPreview
	payload["stderr"] = stderrPreview
	payload["output_captured"] = true
	payload["output_capture"] = capture.descriptor()
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode captured response: %w", err)
	}
	return injectResult{StatusCode: response.StatusCode, Body: body}.Summary(), nil
}

type outputReadRequest struct {
	CaptureID  string `json:"capture_id"`
	Stream     string `json:"stream"`
	Mode       string `json:"mode"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Pattern    string `json:"pattern"`
	StartLine  int    `json:"start_line"`
	Context    int    `json:"context"`
	MaxMatches int    `json:"max_matches"`
}

func normalizeOutputReadRequest(request outputReadRequest) (outputReadRequest, error) {
	if request.Stream == "" {
		request.Stream = "stdout"
	}
	if request.Mode == "" {
		request.Mode = "page"
	}
	if request.Limit == 0 {
		request.Limit = captureReadDefaultChars
	}
	if request.Limit < 1 || request.Limit > captureReadMaxChars {
		return request, fmt.Errorf("limit must be between 1 and %d characters", captureReadMaxChars)
	}
	if request.Offset < 0 {
		return request, errors.New("offset must be zero or greater")
	}
	if request.StartLine < 0 {
		return request, errors.New("start_line must be zero or greater")
	}
	if request.Context < 0 || request.Context > captureSearchMaxContext {
		return request, fmt.Errorf("context must be between 0 and %d lines", captureSearchMaxContext)
	}
	if request.MaxMatches == 0 {
		request.MaxMatches = 20
	}
	if request.MaxMatches < 1 || request.MaxMatches > captureSearchMaxMatches {
		return request, fmt.Errorf("max_matches must be between 1 and %d", captureSearchMaxMatches)
	}
	switch request.Mode {
	case "page", "tail":
		if request.Pattern != "" {
			return request, errors.New("pattern is only valid in search mode")
		}
	case "search":
		if request.Pattern == "" {
			return request, errors.New("pattern is required in search mode")
		}
		if len(request.Pattern) > captureSearchMaxPattern {
			return request, fmt.Errorf("pattern is longer than %d bytes", captureSearchMaxPattern)
		}
	default:
		return request, errors.New("mode must be page, tail, or search")
	}
	return request, nil
}

func readCapturedOutput(capture *capturedOutput, rawRequest outputReadRequest) (map[string]any, error) {
	request, err := normalizeOutputReadRequest(rawRequest)
	if err != nil {
		return nil, err
	}
	content, ok := capture.Streams[request.Stream]
	if !ok {
		names := make([]string, 0, len(capture.Streams))
		for name := range capture.Streams {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("stream %q is not available; choose one of %s",
			request.Stream, strings.Join(names, ", "))
	}

	result := map[string]any{
		"capture_id":       capture.ID,
		"stream":           request.Stream,
		"mode":             request.Mode,
		"expires_at":       capture.ExpiresAt.UTC().Format(time.RFC3339),
		"source_truncated": capture.SourceTruncated,
	}
	if request.Mode == "search" {
		search, err := searchCapturedOutput(content, request)
		if err != nil {
			return nil, err
		}
		for key, value := range search {
			result[key] = value
		}
		return result, nil
	}

	runes := []rune(content)
	start := request.Offset
	if request.Mode == "tail" {
		start = len(runes) - request.Limit
		if start < 0 {
			start = 0
		}
	} else if start > len(runes) {
		start = len(runes)
	}
	end := start + request.Limit
	if end > len(runes) {
		end = len(runes)
	}
	result["offset"] = start
	result["next_offset"] = end
	result["limit"] = request.Limit
	result["total_chars"] = len(runes)
	result["eof"] = end == len(runes)
	result["content"] = string(runes[start:end])
	return result, nil
}

func splitOutputLines(content string) []string {
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	if strings.HasSuffix(content, "\n") {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func searchCapturedOutput(content string, request outputReadRequest) (map[string]any, error) {
	expression, err := regexp.Compile(request.Pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid RE2 pattern: %w", err)
	}
	lines := splitOutputLines(content)
	if request.StartLine > len(lines) {
		request.StartLine = len(lines)
	}

	var builder strings.Builder
	matchLines := make([]int, 0, request.MaxMatches)
	nextStart := len(lines)
	lastEmitted := -1
	written := 0
	contentTruncated := false

	for lineIndex := request.StartLine; lineIndex < len(lines); lineIndex++ {
		if !expression.MatchString(lines[lineIndex]) {
			continue
		}
		blockStart := lineIndex - request.Context
		if blockStart < 0 {
			blockStart = 0
		}
		if blockStart <= lastEmitted {
			blockStart = lastEmitted + 1
		}
		blockEnd := lineIndex + request.Context + 1
		if blockEnd > len(lines) {
			blockEnd = len(lines)
		}

		var block strings.Builder
		for selected := blockStart; selected < blockEnd; selected++ {
			fmt.Fprintf(&block, "%d:%s\n", selected+1, lines[selected])
		}
		blockRunes := []rune(block.String())
		remaining := request.Limit - written
		if len(blockRunes) > remaining {
			if len(matchLines) == 0 && remaining > 0 {
				builder.WriteString(string(blockRunes[:remaining]))
				matchLines = append(matchLines, lineIndex+1)
				nextStart = lineIndex + 1
			} else {
				nextStart = lineIndex
			}
			contentTruncated = true
			break
		}
		builder.WriteString(string(blockRunes))
		written += len(blockRunes)
		matchLines = append(matchLines, lineIndex+1)
		lastEmitted = blockEnd - 1
		nextStart = lineIndex + 1
		if len(matchLines) >= request.MaxMatches {
			contentTruncated = nextStart < len(lines)
			break
		}
	}
	if !contentTruncated {
		nextStart = len(lines)
	}

	return map[string]any{
		"pattern":           request.Pattern,
		"start_line":        request.StartLine,
		"next_start_line":   nextStart,
		"total_lines":       len(lines),
		"match_lines":       matchLines,
		"match_count":       len(matchLines),
		"max_matches":       request.MaxMatches,
		"context":           request.Context,
		"content":           builder.String(),
		"content_truncated": contentTruncated,
		"eof":               nextStart >= len(lines),
	}, nil
}
