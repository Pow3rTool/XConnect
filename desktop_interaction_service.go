package main

import (
	"context"
	"errors"
	"time"
)

type desktopTerminalInteraction struct {
	Owner   captureOwner
	Node    string
	At      time.Time
	Receipt map[string]any
}

type desktopInteractionOwner struct {
	Owner   captureOwner
	ID      string
	Session uint32
	Expires time.Time
}

func (s *DesktopService) interact(ctx context.Context, owner captureOwner, node string, r desktopRequest, rid string, audit desktopAudit) (map[string]any, int) {
	spec := *r.Interaction
	fail := func(err error) (map[string]any, int) {
		return map[string]any{"ok": false, "error": err.Error(), "interaction_id": spec.ID, "instruction": "Never replay input after an uncertain result. Release the interaction or wait for its lease to expire."}, 409
	}
	if check, ok := ctx.Value(desktopAuthorizeKey{}).(func() error); ok {
		if err := check(); err != nil {
			return fail(err)
		}
	}
	s.mu.Lock()
	if s.interactions == nil {
		s.interactions = map[string]desktopInteractionOwner{}
	}
	current, exists := s.interactions[node]
	if exists && time.Now().After(current.Expires) {
		delete(s.interactions, node)
		exists = false
	}
	var ended *desktopTerminalInteraction
	for id, e := range s.endedInteractions {
		if time.Since(e.At) > 180*time.Second {
			delete(s.endedInteractions, id)
			continue
		}
		if id == spec.ID && e.Owner == owner && e.Node == node {
			copy := e
			ended = &copy
		}
	}
	s.mu.Unlock()
	if spec.Operation != "begin" && ended != nil {
		return cloneDesktopReceipt(ended.Receipt), 409
	}
	var session uint32
	if spec.Operation == "begin" {
		if exists {
			return fail(errors.New("desktop already has an active interaction"))
		}
		f, err := s.frame(owner, node, r.FrameID)
		if err != nil {
			return fail(err)
		}
		if f.Observation["actionable"] != true || f.Observation["interaction_id"] != nil {
			return fail(errors.New("begin requires a fresh ordinary desktop observation"))
		}
		session = uint32(number(f.Observation["session_id"]))
		if session == 0 {
			return fail(errors.New("observation lacks a usable session"))
		}
		spec.ID = newID()
		current = desktopInteractionOwner{Owner: owner, ID: spec.ID, Session: session}
	} else {
		if !exists || current.Owner != owner || current.ID != spec.ID {
			return fail(errors.New("interaction unavailable, expired, or owned by another caller"))
		}
		session = current.Session
		if spec.Operation == "continue" {
			f, err := s.frame(owner, node, r.FrameID)
			if err != nil {
				return fail(err)
			}
			if f.Observation["interaction_id"] != spec.ID || f.Observation["actionable"] != true {
				return fail(errors.New("continue requires this interaction's final checkpoint"))
			}
		}
	}
	lease := spec.LeaseMS
	if lease == 0 {
		lease = 60000
	}
	// Reserve before dispatch, including when the node receipt is lost. The
	// node independently enforces its lease and the 5-minute lifetime.
	current.Expires = time.Now().Add(time.Duration(lease+15000) * time.Millisecond)
	s.mu.Lock()
	s.interactions[node] = current
	s.mu.Unlock()
	request := map[string]any{"op": "interact", "session_id": session, "frame_id": r.FrameID, "interaction": spec}
	out, err := s.dispatch(ctx, owner, node, request, rid, audit)
	if err != nil {
		return fail(err)
	}
	reject := func(problem error) (map[string]any, int) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		ended, e := s.backend(cleanup, node, map[string]any{"id": newID(), "op": "interact", "session_id": session, "interaction": DesktopInteraction{ID: spec.ID, Operation: "cancel"}})
		cancel()
		if e == nil && ended["released"] == true {
			s.mu.Lock()
			delete(s.interactions, node)
			s.mu.Unlock()
		}
		return fail(problem)
	}
	if frames, ok := out["frames"].([]any); ok {
		if len(frames) > 5 {
			return reject(errors.New("too many interaction images; cancellation requested"))
		}
		for _, frame := range frames {
			f, ok := frame.(map[string]any)
			if !ok {
				return reject(errors.New("invalid intermediate frame; cancellation requested"))
			}
			if err := s.remember(owner, node, f); err != nil {
				return reject(err)
			}
		}
	}
	// Cancellation of the HTTP request must not leave input held until a model
	// that will never receive the frame eventually responds.
	if ctx.Err() != nil && out["interaction_state"] == "thinking" {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		ended, e := s.backend(cleanup, node, map[string]any{"id": newID(), "op": "interact", "session_id": session, "interaction": DesktopInteraction{ID: spec.ID, Operation: "cancel"}})
		cancel()
		if e == nil && ended["released"] == true {
			s.mu.Lock()
			delete(s.interactions, node)
			s.mu.Unlock()
		}
		return fail(errors.New("caller disconnected; interaction cancellation requested"))
	}
	s.mu.Lock()
	if out["interaction_state"] == "thinking" {
		if expiry, err := time.Parse(time.RFC3339Nano, asStr(out["expires_at"])); err == nil {
			current.Expires = minDesktopExpiry(expiry, time.Now().Add(65*time.Second))
			s.interactions[node] = current
		}
	} else if out["released"] == true || out["input_status"] == "not_sent" {
		delete(s.interactions, node)
		if out["ok"] != true && out["released"] == true {
			if s.endedInteractions == nil {
				s.endedInteractions = map[string]desktopTerminalInteraction{}
			}
			if len(s.endedInteractions) >= 64 {
				for id := range s.endedInteractions {
					delete(s.endedInteractions, id)
					break
				}
			}
			s.endedInteractions[spec.ID] = desktopTerminalInteraction{owner, node, time.Now(), cloneDesktopReceipt(out)}
		}
	}
	s.mu.Unlock()
	if r.IncludeImage != nil && !*r.IncludeImage {
		out = desktopWithoutImage(out)
	}
	if out["ok"] != true {
		return out, 409
	}
	return out, 200
}
func minDesktopExpiry(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Terminal receipts carry the cause and pause/release state, never screenshot bytes.
func cloneDesktopReceipt(out map[string]any) map[string]any {
	r := map[string]any{}
	for _, k := range []string{"ok", "error", "interaction_id", "interaction_state", "input_status", "released", "paused", "pause_error", "ended_at", "broker_version"} {
		if v, ok := out[k]; ok {
			r[k] = v
		}
	}
	return r
}
