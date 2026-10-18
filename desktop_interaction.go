package main

import (
	"errors"
	"strings"
)

// An interaction is a bounded series of input events with visual checkpoints.
// Only the final checkpoint may authorize the next request.
type DesktopInputEvent struct {
	Type       string `json:"type"`
	Key        string `json:"key,omitempty"`
	Button     string `json:"button,omitempty"`
	X          *int   `json:"x,omitempty"`
	Y          *int   `json:"y,omitempty"`
	DurationMS int    `json:"duration_ms,omitempty"`
	Samples    int    `json:"samples,omitempty"`
}
type DesktopInteraction struct {
	ID        string              `json:"interaction_id,omitempty"`
	Operation string              `json:"operation"`
	LeaseMS   int                 `json:"lease_ms,omitempty"`
	Events    []DesktopInputEvent `json:"events,omitempty"`
}

func validInteractionKey(key string) bool {
	return key != "" && !strings.Contains(key, "+") && validDesktopChord(key)
}
func validateDesktopInteraction(i *DesktopInteraction) error {
	if i == nil {
		return errors.New("interaction required")
	}
	switch i.Operation {
	case "begin", "continue", "observe", "release", "cancel":
	default:
		return errors.New("invalid interaction operation")
	}
	if i.LeaseMS != 0 && (i.LeaseMS < 1000 || i.LeaseMS > 60000) {
		return errors.New("lease_ms must be 1000..60000; default 60000")
	}
	if len(i.Events) > 16 {
		return errors.New("at most 16 input events per call")
	}
	if i.Operation != "begin" && i.Operation != "continue" && len(i.Events) > 0 {
		return errors.New("only begin/continue accept input events")
	}
	total, frames := 0, 1 // always return a final checkpoint
	for _, e := range i.Events {
		if e.DurationMS < 0 || e.DurationMS > 3000 || e.Samples < 0 || e.Samples > 4 {
			return errors.New("duration_ms must be 0..3000 and samples 0..4")
		}
		if e.Type != "move" && e.Type != "wait" && e.DurationMS != 0 {
			return errors.New("duration_ms only applies to move/wait")
		}
		if e.Type != "move" && e.Samples != 0 {
			return errors.New("samples only applies to move")
		}
		if e.Type != "move" && (e.X != nil || e.Y != nil) {
			return errors.New("coordinates only apply to move")
		}
		if e.Type != "key_down" && e.Type != "key_up" && e.Type != "key_press" && e.Key != "" {
			return errors.New("key requires a keyboard event")
		}
		if e.Type != "button_down" && e.Type != "button_up" && e.Button != "" {
			return errors.New("button requires a button event")
		}
		switch e.Type {
		case "key_down", "key_up", "key_press":
			if !validInteractionKey(e.Key) {
				return errors.New("event requires one named key; hold modifiers with key_down")
			}
			if e.Type == "key_press" {
				total += 80
			}
		case "button_down", "button_up":
			if e.Button != "left" && e.Button != "right" && e.Button != "middle" {
				return errors.New("event requires left/right/middle button")
			}
		case "move":
			if e.X == nil || e.Y == nil || *e.X < 0 || *e.Y < 0 || *e.X > 16000 || *e.Y > 16000 {
				return errors.New("move requires x/y")
			}
			if e.Samples > 0 && e.DurationMS < 100 {
				return errors.New("sampled movement requires duration_ms >=100")
			}
			frames += e.Samples
		case "wait":
			if e.DurationMS < 1 {
				return errors.New("wait requires duration_ms")
			}
		case "capture":
			frames++
		default:
			return errors.New("unsupported interaction event")
		}
		total += e.DurationMS
	}
	if total > 10000 {
		return errors.New("input sequence exceeds 10 seconds")
	}
	if frames > 6 {
		return errors.New("at most six images per response, including final checkpoint")
	}
	return nil
}
