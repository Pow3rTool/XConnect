package main

import "testing"

func TestInteractionLimitsBeforeInput(t *testing.T) {
	p := 10
	good := DesktopInteraction{Operation: "begin", Events: []DesktopInputEvent{{Type: "key_down", Key: "CTRL"}, {Type: "key_press", Key: "TAB"}, {Type: "wait", DurationMS: 200}, {Type: "capture"}}}
	if err := validateDesktopInteraction(&good); err != nil {
		t.Fatal(err)
	}
	cases := []DesktopInteraction{
		{Operation: "begin", LeaseMS: 60001},
		{Operation: "release", Events: good.Events},
		{Operation: "continue", Events: []DesktopInputEvent{{Type: "key_down", Key: "CTRL+TAB"}}},
		{Operation: "begin", Events: []DesktopInputEvent{{Type: "button_up", Button: "any"}}},
		{Operation: "begin", Events: []DesktopInputEvent{{Type: "move", X: &p, Y: &p, Samples: 4, DurationMS: 3000}, {Type: "move", X: &p, Y: &p, Samples: 4, DurationMS: 3000}}},
		{Operation: "begin", Events: []DesktopInputEvent{{Type: "wait", DurationMS: 3000}, {Type: "wait", DurationMS: 3000}, {Type: "wait", DurationMS: 3000}, {Type: "wait", DurationMS: 3000}}},
		{Operation: "begin", Events: []DesktopInputEvent{{Type: "capture", Key: "A"}}},
	}
	for _, c := range cases {
		if err := validateDesktopInteraction(&c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
