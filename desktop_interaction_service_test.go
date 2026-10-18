package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestInteractionOwnershipCheckpointsAndRelease(t *testing.T) {
	s := desktopTestService()
	calls := 0
	initial := desktopFixture()
	initial["observation"].(map[string]any)["actionable"] = true
	if err := s.remember(desktopOwner, "node", initial); err != nil {
		t.Fatal(err)
	}
	s.backend = func(_ context.Context, _ string, req map[string]any) (map[string]any, error) {
		calls++
		i := req["interaction"].(DesktopInteraction)
		out := desktopFixture()
		obs := out["observation"].(map[string]any)
		obs["actionable"] = true
		out["interaction_id"] = i.ID
		if i.Operation == "cancel" || i.Operation == "release" {
			out["released"] = true
			out["interaction_state"] = "released"
			return out, nil
		}
		obs["interaction_id"] = i.ID
		out["interaction_state"] = "thinking"
		out["expires_at"] = time.Now().Add(time.Minute).Format(time.RFC3339Nano)
		mid := desktopFixture()
		mid["observation"].(map[string]any)["actionable"] = false
		mid["observation"].(map[string]any)["interaction_id"] = i.ID
		out["frames"] = []any{mid}
		return out, nil
	}
	invoke := func(owner captureOwner, r desktopRequest) (map[string]any, int) {
		return s.execute(context.Background(), owner, "node", "interact", r, "parent", noDesktopAudit)
	}
	out, code := invoke(desktopOwner, desktopRequest{FrameID: asStr(initial["observation"].(map[string]any)["frame_id"]), Interaction: &DesktopInteraction{Operation: "begin"}})
	if code != 200 {
		t.Fatal(code, out)
	}
	id := asStr(out["interaction_id"])
	final := asStr(out["observation"].(map[string]any)["frame_id"])
	for _, owner := range []captureOwner{{"other", "user", "app"}, {"tenant", "other", "app"}, {"tenant", "user", "other"}} {
		if _, code := invoke(owner, desktopRequest{Interaction: &DesktopInteraction{ID: id, Operation: "cancel"}}); code != 409 {
			t.Fatal("cross-owner cancellation allowed")
		}
	}
	if calls != 1 {
		t.Fatal("cross-owner input sent")
	}
	if _, code := s.execute(context.Background(), desktopOwner, "node", "observe", desktopRequest{}, "p", noDesktopAudit); code != 409 {
		t.Fatal("ordinary observation interfered")
	}
	mid := out["frames"].([]any)[0].(map[string]any)
	if _, code := invoke(desktopOwner, desktopRequest{FrameID: asStr(mid["observation"].(map[string]any)["frame_id"]), Interaction: &DesktopInteraction{ID: id, Operation: "continue"}}); code != 409 {
		t.Fatal("intermediate frame authorized input")
	}
	if _, code := invoke(desktopOwner, desktopRequest{FrameID: final, Interaction: &DesktopInteraction{ID: id, Operation: "continue"}}); code != 200 {
		t.Fatal("checkpoint refused")
	}
	if _, code := invoke(desktopOwner, desktopRequest{Interaction: &DesktopInteraction{ID: id, Operation: "release"}}); code != 200 {
		t.Fatal("release required a frame")
	}
	if len(s.interactions) != 0 {
		t.Fatal("release left ownership reserved")
	}
}
func TestInteractionAuditOmitsAllPixels(t *testing.T) {
	out := desktopFixture()
	out["frames"] = []any{desktopFixture(), desktopFixture()}
	raw, _ := json.Marshal(desktopWithoutImage(out))
	if strings.Contains(string(raw), "/9j/") || strings.Contains(string(raw), "\"data\"") {
		t.Fatal("image bytes in audit")
	}
	if !strings.Contains(string(raw), "sha256") {
		t.Fatal("lost frame evidence")
	}
}
func TestInteractionCallerCancellationReleases(t *testing.T) {
	s := desktopTestService()
	initial := desktopFixture()
	initial["observation"].(map[string]any)["actionable"] = true
	_ = s.remember(desktopOwner, "node", initial)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	s.backend = func(_ context.Context, _ string, req map[string]any) (map[string]any, error) {
		calls++
		i := req["interaction"].(DesktopInteraction)
		if calls == 2 {
			if i.Operation != "cancel" {
				t.Fatal("did not cancel")
			}
			return map[string]any{"released": true}, nil
		}
		cancel()
		out := desktopFixture()
		out["interaction_state"] = "thinking"
		return out, nil
	}
	_, code := s.execute(ctx, desktopOwner, "node", "interact", desktopRequest{FrameID: asStr(initial["observation"].(map[string]any)["frame_id"]), Interaction: &DesktopInteraction{Operation: "begin"}}, "p", noDesktopAudit)
	if code != 409 || calls != 2 || len(s.interactions) != 0 {
		t.Fatal(code, calls, s.interactions)
	}
}

func TestInterruptedReceiptSurvivesBrokerRelease(t *testing.T) {
	s := desktopTestService()
	initial := desktopFixture()
	initial["observation"].(map[string]any)["actionable"] = true
	_ = s.remember(desktopOwner, "node", initial)
	calls := 0
	s.backend = func(_ context.Context, _ string, req map[string]any) (map[string]any, error) {
		calls++
		i := req["interaction"].(DesktopInteraction)
		return map[string]any{"ok": false, "interaction_id": i.ID, "interaction_state": "cancelled", "input_status": "sent", "error": "outside Escape triple-press", "released": true, "paused": true}, nil
	}
	out, code := s.execute(context.Background(), desktopOwner, "node", "interact", desktopRequest{FrameID: asStr(initial["observation"].(map[string]any)["frame_id"]), Interaction: &DesktopInteraction{Operation: "begin"}}, "p", noDesktopAudit)
	if code != 409 || out["paused"] != true {
		t.Fatal(code, out)
	}
	id := asStr(out["interaction_id"])
	for _, op := range []string{"observe", "continue", "release"} {
		again, code := s.execute(context.Background(), desktopOwner, "node", "interact", desktopRequest{Interaction: &DesktopInteraction{ID: id, Operation: op}}, "p", noDesktopAudit)
		if code != 409 || again["error"] != "outside Escape triple-press" || again["released"] != true {
			t.Fatal(op, code, again)
		}
	}
	other := captureOwner{"other", "user", "app"}
	foreign, _ := s.execute(context.Background(), other, "node", "interact", desktopRequest{Interaction: &DesktopInteraction{ID: id, Operation: "observe"}}, "p", noDesktopAudit)
	if foreign["paused"] != nil {
		t.Fatal("terminal receipt leaked across owners")
	}
	if calls != 1 {
		t.Fatal("terminal retry reached node", calls)
	}
}
