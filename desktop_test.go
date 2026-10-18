package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func desktopFixture() map[string]any {
	var b bytes.Buffer
	_ = jpeg.Encode(&b, image.NewRGBA(image.Rect(0, 0, 160, 100)), nil)
	h := sha256.Sum256(b.Bytes())
	return map[string]any{"ok": true, "input_status": "sent", "observation": map[string]any{"frame_id": newID(), "session_id": float64(7), "image_width": 160, "image_height": 100, "sha256": hex.EncodeToString(h[:])}, "image": map[string]any{"mimeType": "image/jpeg", "data": base64.StdEncoding.EncodeToString(b.Bytes())}}
}
func desktopTestService() *DesktopService {
	return &DesktopService{busy: map[string]bool{}, frames: map[string]desktopFrame{}}
}
func noDesktopAudit(string, map[string]any, map[string]any) {}

var desktopOwner = captureOwner{"tenant", "user", "app"}

func TestDesktopPointRejectsUnsafeOutputs(t *testing.T) {
	for _, s := range []string{"[0.5,0.5]", "(160,50)", "(10,100)", "(-1,5)", "(4,5) click()", "NOT_FOUND", "(9999999999999999999999999,1)", "(1.2,3)"} {
		if _, _, e := parseDesktopPoint(s, 160, 100); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if x, y, e := parseDesktopPoint(" (0, 99) ", 160, 100); e != nil || x != 0 || y != 99 {
		t.Fatal(x, y, e)
	}
}
func TestDesktopFrameOwnershipExpiryAndIntegrity(t *testing.T) {
	s := desktopTestService()
	out := desktopFixture()
	id := asStr(out["observation"].(map[string]any)["frame_id"])
	if e := s.remember(desktopOwner, "node", out); e != nil {
		t.Fatal(e)
	}
	for _, owner := range []captureOwner{{"other", "user", "app"}, {"tenant", "other", "app"}, {"tenant", "user", "other"}} {
		if _, e := s.frame(owner, "node", id); e == nil {
			t.Fatal("cross-owner read")
		}
	}
	if _, e := s.frame(desktopOwner, "other", id); e == nil {
		t.Fatal("cross-host read")
	}
	f := s.frames[id]
	f.Created = time.Now().Add(-181 * time.Second)
	s.frames[id] = f
	if _, e := s.frame(desktopOwner, "node", id); e == nil {
		t.Fatal("expired frame")
	}
	out["observation"].(map[string]any)["sha256"] = "wrong"
	if e := s.remember(desktopOwner, "node", out); e == nil {
		t.Fatal("hash mismatch accepted")
	}
}
func TestDesktopFrameCacheBound(t *testing.T) {
	s := desktopTestService()
	for i := 0; i < 70; i++ {
		if e := s.remember(desktopOwner, "node", desktopFixture()); e != nil {
			t.Fatal(e)
		}
	}
	if len(s.frames) != 64 {
		t.Fatal(len(s.frames))
	}
}
func TestDesktopActionSchema(t *testing.T) {
	p := 10
	bad := []DesktopAction{{Action: "shell", Text: "calc"}, {Action: "click", Target: "Save", X: &p, Y: &p}, {Action: "key", Key: "UNKNOWN"}, {Action: "type", Text: "a", Key: "ENTER"}, {Action: "scroll", X: &p, Y: &p, Axis: "vertical", Steps: 21}, {Action: "drag", X: &p, Y: &p, ToX: &p, ToY: &p, DurationMS: 4000}}
	for _, a := range bad {
		if validateDesktopAction(a) == nil {
			t.Fatalf("accepted %+v", a)
		}
	}
	for _, a := range []DesktopAction{{Action: "click", Target: "menu", Button: "right"}, {Action: "drag", X: &p, Y: &p, ToX: &p, ToY: &p, DurationMS: 200, Button: "middle"}, {Action: "key", Key: "SHIFT+RIGHT"}} {
		if e := validateDesktopAction(a); e != nil {
			t.Fatal(e)
		}
	}
}
func TestDesktopChordGrammar(t *testing.T) {
	for _, key := range []string{"CTRL+TAB", "Control+Tab", "CTRL+SHIFT+TAB", " alt + tab ", "A", "9", "F24", "WIN", "CTRL", "SHIFT", "CTRL+ALT+SHIFT+WIN+F12", "SPACE", "INS", "PGDN", "RETURN", "ESCAPE"} {
		if !validDesktopChord(key) {
			t.Errorf("rejected %q", key)
		}
	}
	for _, key := range []string{"", "BOGUS", "CTRL+CONTROL+A", "CTRL+CTRL+A", "CTRL+", "+TAB", "A+B", "CTRL+SHIFT", "F0", "F25", "{ENTER}", "CTRL++A", "CTRL+A+TAB", "é", strings.Repeat(" ", 65) + "A"} {
		if validDesktopChord(key) {
			t.Errorf("accepted %q", key)
		}
	}
}
func TestDesktopTaskStopsAtRefusedInput(t *testing.T) {
	s := desktopTestService()
	calls := 0
	s.backend = func(context.Context, string, map[string]any) (map[string]any, error) {
		calls++
		if calls == 3 {
			return map[string]any{"ok": false, "input_status": "not_sent", "error": "input_changed"}, nil
		}
		return desktopFixture(), nil
	}
	r := desktopRequest{Steps: []DesktopAction{{Action: "key", Key: "TAB"}, {Action: "key", Key: "ENTER"}, {Action: "type", Text: "never"}}}
	out, code := s.execute(context.Background(), desktopOwner, "node", "task", r, "parent", noDesktopAudit)
	if calls != 3 || code != 409 || out["goal_verified"] != false || len(out["steps"].([]map[string]any)) != 2 {
		t.Fatal(calls, code, out)
	}
}
func TestDesktopTaskGroundingAndOptionalImage(t *testing.T) {
	s := desktopTestService()
	groundings := 0
	frames := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		groundings++
		if r.Header.Get("Authorization") != "Bearer test-service-key" {
			t.Error("missing service credential")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["model"] != "gui-grounder" {
			t.Error(body)
		}
		w.Header().Set("X-Nexus-Request-Id", "42")
		_, _ = w.Write([]byte(`{"model":"ui-tars","choices":[{"message":{"content":"(40,50)"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	s.client = server.Client()
	s.nexusURL = server.URL
	s.nexusKey = "test-service-key"
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		if r["op"] == "act" {
			if r["x"] != float64(40) || r["y"] != float64(50) {
				t.Fatal(r)
			}
			frames = append(frames, asStr(r["frame_id"]))
		}
		return desktopFixture(), nil
	}
	off := false
	r := desktopRequest{IncludeImage: &off, Steps: []DesktopAction{{Action: "click", Target: "View"}, {Action: "click", Target: "Zoom"}}}
	audit := func(_ string, _ map[string]any, result map[string]any) {
		raw, _ := json.Marshal(result)
		if bytes.Contains(raw, []byte("/9j/")) {
			t.Error("image leaked to audit")
		}
	}
	out, code := s.execute(context.Background(), desktopOwner, "node", "task", r, "parent", audit)
	if code != 200 || groundings != 2 || len(frames) != 2 || frames[0] == frames[1] || out["image"] != nil {
		t.Fatal(code, groundings, frames, out)
	}
	id := asStr(out["observation"].(map[string]any)["frame_id"])
	if _, e := s.frame(desktopOwner, "node", id); e != nil {
		t.Fatal("compact response lost screenshot", e)
	}
}
func TestDesktopCancellationAndBusyDoNotDispatch(t *testing.T) {
	s := desktopTestService()
	s.backend = func(context.Context, string, map[string]any) (map[string]any, error) {
		t.Fatal("dispatched")
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, code := s.execute(ctx, desktopOwner, "node", "observe", desktopRequest{}, "id", noDesktopAudit); code != 409 {
		t.Fatal(code)
	}
	s.busy["node"] = true
	if _, code := s.execute(context.Background(), desktopOwner, "node", "observe", desktopRequest{}, "id", noDesktopAudit); code != 409 {
		t.Fatal(code)
	}
}
func TestDesktopTransportFailureDoesNotRepeat(t *testing.T) {
	s := desktopTestService()
	calls := 0
	s.backend = func(context.Context, string, map[string]any) (map[string]any, error) {
		calls++
		if calls == 1 {
			return desktopFixture(), nil
		}
		return nil, errors.New("unknown dispatch outcome")
	}
	out, code := s.execute(context.Background(), desktopOwner, "node", "task", desktopRequest{Steps: []DesktopAction{{Action: "key", Key: "TAB"}, {Action: "key", Key: "ENTER"}}}, "id", noDesktopAudit)
	if code != 409 || calls != 2 || out["image_is_last_observation"] != true {
		t.Fatal(code, calls, out)
	}
}
func TestDesktopAuditDoesNotStoreTypedText(t *testing.T) {
	a := DesktopAction{Action: "type", Text: "private document"}
	out, _ := json.Marshal(desktopActionSummary(&a))
	if strings.Contains(string(out), a.Text) || !strings.Contains(string(out), "text_sha256") {
		t.Fatal(string(out))
	}
}

func TestDesktopAbsentTargetKeepsModelReceiptAndDoesNotClick(t *testing.T) {
	s := desktopTestService()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"model":"ui-tars","choices":[{"message":{"content":"NOT_FOUND"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	s.client = server.Client()
	s.nexusURL = server.URL
	s.backend = func(context.Context, string, map[string]any) (map[string]any, error) {
		calls++
		return desktopFixture(), nil
	}
	out, code := s.execute(context.Background(), desktopOwner, "node", "task", desktopRequest{Steps: []DesktopAction{{Action: "click", Target: "absent"}}}, "parent", noDesktopAudit)
	if code != 409 || calls != 1 {
		t.Fatal(code, calls)
	}
	receipt := out["steps"].([]map[string]any)[0]["grounding"].(map[string]any)
	if receipt["grounding_status"] != "not_found" || receipt["output"] != "NOT_FOUND" {
		t.Fatal(receipt)
	}
}

func TestDesktopCapabilityRequiresWindowsAndAdvertisement(t *testing.T) {
	b := &Broker{}
	for _, runtime := range []nodeVer{{GOOS: "windows"}, {GOOS: "linux", Capabilities: map[string]bool{"desktop": true}}, {GOOS: "windows", Capabilities: map[string]bool{"desktop": false}}} {
		b.versions.Store("node", runtime)
		if b.supportsDesktop("node") {
			t.Fatal("unsupported node accepted")
		}
	}
	b.versions.Store("node", nodeVer{GOOS: "windows", Capabilities: map[string]bool{"desktop": true}})
	if !b.supportsDesktop("node") {
		t.Fatal("upgraded Windows node rejected")
	}
}
func TestDesktopIndependentNodesAndSessionBinding(t *testing.T) {
	s := desktopTestService()
	s.busy["busy-node"] = true
	s.backend = func(_ context.Context, node string, r map[string]any) (map[string]any, error) {
		if node != "other-node" {
			t.Fatal(node)
		}
		if r["op"] == "observe" && r["session_id"] != uint32(7) {
			t.Fatal("session selection lost", r)
		}
		if r["op"] == "act" && r["session_id"] != float64(7) {
			t.Fatal("frame session lost", r)
		}
		return desktopFixture(), nil
	}
	out, code := s.execute(context.Background(), desktopOwner, "other-node", "task", desktopRequest{SessionID: 7, Steps: []DesktopAction{{Action: "key", Key: "TAB"}}}, "parent", noDesktopAudit)
	if code != 200 {
		t.Fatal(code, out)
	}
}

func TestDesktopUnstableObservationCannotSendInput(t *testing.T) {
	s := desktopTestService()
	out := desktopFixture()
	obs := out["observation"].(map[string]any)
	obs["actionable"] = false
	if err := s.remember(desktopOwner, "node", out); err != nil {
		t.Fatal(err)
	}
	s.backend = func(context.Context, string, map[string]any) (map[string]any, error) {
		t.Fatal("dispatched unstable frame")
		return nil, nil
	}
	_, err := s.act(context.Background(), desktopOwner, "node", asStr(obs["frame_id"]), DesktopAction{Action: "key", Key: "TAB"}, "parent", noDesktopAudit)
	if err == nil {
		t.Fatal("unstable frame accepted")
	}
}
func desktopFixtureFocus(hwnd, class, title string, caps bool) map[string]any {
	out := desktopFixture()
	obs := out["observation"].(map[string]any)
	obs["foreground"] = map[string]any{"hwnd": hwnd, "class": class, "title": title}
	if caps {
		obs["capabilities"] = map[string]any{"foreground_expectation": true}
	}
	return out
}
func TestDesktopTaskReportsFocusAndExpectation(t *testing.T) {
	s := desktopTestService()
	acts := 0
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		if r["op"] == "observe" {
			return desktopFixtureFocus("0x10", "Shell_TrayWnd", "", true), nil
		}
		acts++
		if acts == 2 {
			want := map[string]any{"class": "#32770", "title": "Run"}
			if got, _ := r["expect_foreground"].(map[string]any); got["class"] != want["class"] || got["title"] != want["title"] {
				t.Fatal("expectation not forwarded to the node", r)
			}
		}
		return desktopFixtureFocus("0x20", "#32770", "Run", true), nil
	}
	r := desktopRequest{Steps: []DesktopAction{{Action: "key", Key: "WIN+R"}, {Action: "type", Text: "notepad", ExpectForeground: &DesktopWindowMatch{Class: "#32770", Title: "Run"}}}}
	out, code := s.execute(context.Background(), desktopOwner, "node", "task", r, "parent", noDesktopAudit)
	steps := out["steps"].([]map[string]any)
	if code != 200 || acts != 2 || len(steps) != 2 {
		t.Fatal(code, acts, out)
	}
	first := steps[0]
	if fg := first["foreground_after"].(map[string]any); fg["class"] != "#32770" || fg["title"] != "Run" {
		t.Fatal("receipt lacks where focus landed", first)
	}
	// Fixture JPEGs are identical, so the screenshot did not change while focus did.
	if first["frame_changed"] != false || first["foreground_changed"] != true || steps[1]["foreground_changed"] != false {
		t.Fatal(steps)
	}
}
func TestDesktopExpectationRequiresNodeSupport(t *testing.T) {
	s := desktopTestService()
	old := desktopFixtureFocus("0x10", "Notepad", "Untitled", false)
	if e := s.remember(desktopOwner, "node", old); e != nil {
		t.Fatal(e)
	}
	s.backend = func(context.Context, string, map[string]any) (map[string]any, error) {
		t.Fatal("dispatched an expectation the node cannot enforce")
		return nil, nil
	}
	id := asStr(old["observation"].(map[string]any)["frame_id"])
	a := DesktopAction{Action: "type", Text: "x", ExpectForeground: &DesktopWindowMatch{Class: "Notepad"}}
	if _, e := s.act(context.Background(), desktopOwner, "node", id, a, "parent", noDesktopAudit); e == nil || !strings.Contains(e.Error(), "upgrade RCON") {
		t.Fatal(e)
	}
}
func TestDesktopExpectationSchema(t *testing.T) {
	ok := DesktopAction{Action: "key", Key: "ENTER", ExpectForeground: &DesktopWindowMatch{Title: "Run"}}
	if e := validateDesktopAction(ok); e != nil {
		t.Fatal(e)
	}
	for _, m := range []*DesktopWindowMatch{{}, {Class: strings.Repeat("c", 257)}, {Title: strings.Repeat("t", 513)}} {
		bad := ok
		bad.ExpectForeground = m
		if validateDesktopAction(bad) == nil {
			t.Fatalf("accepted %+v", m)
		}
	}
}
func TestDesktopCompactLeavesCacheIntact(t *testing.T) {
	caps := map[string]any{"interaction_protocol": "held-v1"}
	obs := map[string]any{"frame_id": "f", "capabilities": caps, "windows": []any{"w"}}
	mid := map[string]any{"frame_id": "m", "capabilities": caps, "windows": []any{"w"}}
	out := map[string]any{"ok": true, "observation": obs, "frames": []any{map[string]any{"observation": mid}}}
	acted := desktopCompact("act", out)
	got := acted["observation"].(map[string]any)
	if got["capabilities"] != nil || got["windows"] == nil {
		t.Fatal("checkpoint should drop capabilities and keep windows", got)
	}
	frame := acted["frames"].([]any)[0].(map[string]any)["observation"].(map[string]any)
	if frame["capabilities"] != nil || frame["windows"] != nil || frame["frame_id"] != "m" {
		t.Fatal("motion frames should be compact", frame)
	}
	if obs["capabilities"] == nil || mid["windows"] == nil {
		t.Fatal("compaction mutated the cached observation")
	}
	if desktopCompact("observe", out)["observation"].(map[string]any)["capabilities"] == nil {
		t.Fatal("observe must still report capabilities")
	}
}
func TestDesktopAttachConsole(t *testing.T) {
	if validateDesktopRequest("attach_console", desktopRequest{Node: "n", SessionID: 2, Force: true}) != nil {
		t.Fatal("valid attach refused")
	}
	for _, r := range []desktopRequest{{Node: "n"}, {Node: "n", SessionID: 2, FrameID: newID()}, {Node: "n", SessionID: 2, WaitMS: 10}} {
		if validateDesktopRequest("attach_console", r) == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if validateDesktopRequest("observe", desktopRequest{Node: "n", Force: true}) == nil {
		t.Fatal("force accepted outside attach_console")
	}
	s := desktopTestService()
	var sent map[string]any
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		sent = r
		out := desktopFixture()
		out["attached_console"] = true
		out["observation"].(map[string]any)["capabilities"] = map[string]any{"console_attach": true}
		return out, nil
	}
	out, code := s.execute(context.Background(), desktopOwner, "node", "attach_console", desktopRequest{Node: "node", SessionID: 2, Force: true}, "parent", noDesktopAudit)
	if code != 200 || sent["op"] != "attach_console" || sent["session_id"] != uint32(2) || sent["force"] != true || out["attached_console"] != true {
		t.Fatal(code, sent, out)
	}
	if _, e := s.frame(desktopOwner, "node", asStr(out["observation"].(map[string]any)["frame_id"])); e != nil {
		t.Fatal("attached frame not usable for the next action", e)
	}
	if desktopCompact("attach_console", out)["observation"].(map[string]any)["capabilities"] == nil {
		t.Fatal("attach result is an observation and keeps capabilities")
	}
	s.backend = func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{"ok": false, "input_status": "not_sent", "error": "session 2 is connected through RDP-Tcp#13; force=true disconnects that client", "sessions": []any{}}, nil
	}
	out, code = s.execute(context.Background(), desktopOwner, "node", "attach_console", desktopRequest{Node: "node", SessionID: 2}, "parent", noDesktopAudit)
	if code != 409 || out["sessions"] == nil || !strings.Contains(asStr(out["error"]), "force=true") {
		t.Fatal("refusal must reach the caller intact", code, out)
	}
}
func TestDesktopWaitAndLaunch(t *testing.T) {
	run := &DesktopWindowMatch{Class: "#32770", Title: "Run"}
	waitAction := DesktopAction{Action: "wait", Until: "foreground", Window: run, DurationMS: 5000}
	if e := validateDesktopRequest("wait", desktopRequest{Node: "n", Action: &waitAction}); e != nil {
		t.Fatal(e)
	}
	if validateDesktopRequest("act", desktopRequest{Node: "n", FrameID: newID(), Action: &waitAction}) == nil {
		t.Fatal("act accepted a wait")
	}
	if validateDesktopRequest("wait", desktopRequest{Node: "n", Action: &DesktopAction{Action: "wait", Until: "foreground", DurationMS: 5000}}) == nil {
		t.Fatal("foreground wait without a window accepted")
	}
	launch := &DesktopLaunch{Command: "omp models", Wait: true, TimeoutMS: 20000}
	if e := validateDesktopRequest("launch", desktopRequest{Node: "n", Launch: launch}); e != nil {
		t.Fatal(e)
	}
	for _, r := range []desktopRequest{{Node: "n", Launch: &DesktopLaunch{Command: "x", Wait: true}}, {Node: "n", Launch: &DesktopLaunch{Command: "x", Wait: true, TimeoutMS: 46000}}, {Node: "n"}} {
		if validateDesktopRequest("launch", r) == nil {
			t.Fatalf("accepted %+v", r.Launch)
		}
	}
	if validateDesktopRequest("observe", desktopRequest{Node: "n", Launch: launch}) == nil {
		t.Fatal("launch fields accepted outside launch")
	}

	s := desktopTestService()
	var sent []map[string]any
	met := true
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		sent = append(sent, r)
		out := desktopFixtureFocus("0x20", "#32770", "Run", true)
		out["observation"].(map[string]any)["capabilities"] = map[string]any{"wait_conditions": []any{"foreground"}}
		if r["op"] == "wait" {
			out["condition_met"] = met
		}
		if r["op"] == "launch" {
			return map[string]any{"ok": true, "input_status": "sent", "exit_code": float64(0), "stdout": "ok"}, nil
		}
		return out, nil
	}
	out, code := s.execute(context.Background(), desktopOwner, "node", "wait", desktopRequest{Node: "node", SessionID: 2, Action: &waitAction}, "parent", noDesktopAudit)
	w := sent[len(sent)-1]
	if code != 200 || out["condition_met"] != true || w["op"] != "wait" || w["until"] != "foreground" || w["duration_ms"] != float64(5000) || w["session_id"] != uint32(2) {
		t.Fatal(code, w, out)
	}
	if win, _ := w["window"].(map[string]any); win["class"] != "#32770" {
		t.Fatal("window match not forwarded", w)
	}

	// In a task, a wait that times out stops the steps after it.
	met, sent = false, nil
	r := desktopRequest{Steps: []DesktopAction{{Action: "key", Key: "WIN+R"}, waitAction, {Action: "type", Text: "never"}}}
	out, code = s.execute(context.Background(), desktopOwner, "node", "task", r, "parent", noDesktopAudit)
	steps := out["steps"].([]map[string]any)
	if code != 409 || len(steps) != 2 || steps[1]["condition_met"] != false || !strings.Contains(asStr(out["error"]), "not met") || len(sent) != 3 {
		t.Fatal(code, len(sent), out)
	}

	sent = nil
	out, code = s.execute(context.Background(), desktopOwner, "node", "launch", desktopRequest{Node: "node", Launch: launch}, "parent", noDesktopAudit)
	l, _ := sent[0]["launch"].(*DesktopLaunch)
	if code != 200 || sent[0]["op"] != "launch" || l == nil || l.Command != "omp models" || out["stdout"] != "ok" {
		t.Fatal(code, sent, out)
	}
}

func TestDesktopRecoveryAuthorizationAndRefusal(t *testing.T) {
	if err := validateDesktopRequest("recover", desktopRequest{Node: "node"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []desktopRequest{{Node: "node", SessionID: 2}, {Node: "node", Force: true}, {Node: "node", FrameID: newID()}, {Node: "node", Launch: &DesktopLaunch{Command: "notepad"}}, {Node: "node", Action: &DesktopAction{Action: "key", Key: "ENTER"}}} {
		if validateDesktopRequest("recover", r) == nil {
			t.Fatal("ambiguous recovery accepted")
		}
	}
	s := desktopTestService()
	calls := 0
	accepted := true
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		calls++
		if r["op"] != "recover" {
			t.Fatal(r)
		}
		return map[string]any{"ok": accepted, "account_disabled": true}, nil
	}
	denied := context.WithValue(context.Background(), desktopAuthorizeKey{}, func() error { return errors.New("revoked") })
	if _, code := s.execute(denied, desktopOwner, "node", "recover", desktopRequest{Node: "node"}, "parent", noDesktopAudit); code == 200 || calls != 0 {
		t.Fatal("revoked caller dispatched", code, calls)
	}
	out, code := s.execute(context.Background(), desktopOwner, "node", "recover", desktopRequest{Node: "node"}, "parent", noDesktopAudit)
	if code != 200 || out["account_disabled"] != true || calls != 1 {
		t.Fatal(code, out, calls)
	}
	accepted = false
	if _, code := s.execute(context.Background(), desktopOwner, "node", "recover", desktopRequest{Node: "node"}, "parent", noDesktopAudit); code != 409 {
		t.Fatal("node refusal lost", code)
	}
}

func TestDesktopLockIsAuthorizedAndHasNoInputPayload(t *testing.T) {
	if e := validateDesktopRequest("lock", desktopRequest{Node: "n", SessionID: 7}); e != nil {
		t.Fatal(e)
	}
	if validateDesktopRequest("lock", desktopRequest{Node: "n", Force: true}) == nil {
		t.Fatal("force accepted")
	}
	s := desktopTestService()
	calls := 0
	s.backend = func(_ context.Context, _ string, r map[string]any) (map[string]any, error) {
		calls++
		if r["op"] != "lock" || r["session_id"] != uint32(7) {
			t.Fatal(r)
		}
		return map[string]any{"ok": true, "locked": true, "verified": true}, nil
	}
	ctx := context.WithValue(context.Background(), desktopAuthorizeKey{}, func() error { return errors.New("revoked") })
	if _, code := s.execute(ctx, desktopOwner, "n", "lock", desktopRequest{Node: "n", SessionID: 7}, "parent", noDesktopAudit); code == 200 || calls != 0 {
		t.Fatal(code, calls)
	}
	if out, code := s.execute(context.Background(), desktopOwner, "n", "lock", desktopRequest{Node: "n", SessionID: 7}, "parent", noDesktopAudit); code != 200 || out["locked"] != true || calls != 1 {
		t.Fatal(code, out, calls)
	}
}
