package main

import "testing"

func TestRunHints(t *testing.T) {
	failed, ok := []byte(`{"rc":1,"stdout":"","stderr":"x"}`), []byte(`{"rc":0,"stdout":"y"}`)
	for name, tc := range map[string]struct {
		goos, command string
		result        []byte
		desktop       bool
		want          string
	}{
		"bash && on windows":         {"windows", "hostname && uname -a", failed, true, hintWindowsShell},
		"grep pipe on windows":       {"windows", "Get-Service | grep rcon", failed, true, hintWindowsShell},
		"bash habit that worked":     {"windows", "echo a && echo b", ok, true, ""},
		"plain powershell failure":   {"windows", "Get-Item C:\\nope", failed, true, ""},
		"gui from session 0":         {"windows", "Start-Process notepad", ok, true, hintSession0},
		"notepad on a desktop node":  {"windows", "notepad C:\\x.txt", ok, true, hintSession0},
		"gui on a non-desktop node":  {"windows", "Start-Process notepad", ok, false, ""},
		"notepad inside a word":      {"windows", "Get-Content mynotepad.txt", ok, true, ""},
		"cmdlet on linux":            {"linux", "Get-ChildItem /etc", failed, false, hintLinuxShell},
		"cmdlet that somehow worked": {"linux", "Get-ChildItem /etc", ok, false, ""},
		"bash failure on linux":      {"linux", "ls /nope && true", failed, false, ""},
		"unparseable result":         {"windows", "a && b", []byte("HTTP 500"), true, ""},
		"unknown os gets nothing":    {"", "a && b", failed, false, ""},
	} {
		if got := runHint(tc.goos, tc.command, tc.result, tc.desktop); got != tc.want {
			t.Errorf("%s: got %q", name, got)
		}
	}
}
