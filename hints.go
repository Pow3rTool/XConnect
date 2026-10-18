package main

import (
	"encoding/json"
	"regexp"
)

// Bumpers for the commonest cross-OS mistakes: Bash habits sent to a Windows
// node, cmdlets sent to a Linux one, and GUI programs started where no user can
// see them. A hint only rides along with a result; it never blocks a command, so
// a false positive costs one sentence.
var (
	hintBashisms       = regexp.MustCompile(`&&|\|\||\|\s*(grep|awk|sed|head|tail|wc|xargs|cut|sort)\b|\bsudo\s|\bexport\s+\w+=|/dev/null|\$\(|\b(systemctl|apt|apt-get|chmod|chown|which|uname)\s|\bls\s+-|<<`)
	hintPowerShellisms = regexp.MustCompile(`\b(Get|Set|New|Remove|Start|Stop|Restart|Test|Invoke|Select|Where|ForEach|Write|Out)-[A-Z][A-Za-z]+`)
	hintGUILaunch      = regexp.MustCompile(`(?i)\b(Start-Process|Invoke-Item)\b|(^|[\s;&|(])(explorer|notepad|mspaint|calc|mstsc)(\.exe)?\b`)
)

const (
	hintWindowsShell = "This is a Windows node: remote_run uses Windows PowerShell 5.1 (no profile), not Bash. " +
		"Use ';' or 'if ($?) { ... }' instead of &&, Select-String instead of grep, Select-Object -First/-Last instead of head/tail, " +
		"$null instead of /dev/null, $env:NAME = 'value' instead of export, and Get-ChildItem -Force instead of ls -la."
	hintLinuxShell = "This is a Linux node: remote_run uses Bash, so PowerShell cmdlets are not available."
	hintSession0   = "remote_run runs as SYSTEM in session 0, so programs it starts are invisible to the signed-in user and GUI programs may exit at once. " +
		"Use desktop_launch to start programs on the user's desktop, as that user."
	hintWindowsACL = "Windows files have ACLs, not POSIX owner/group/mode, so nothing was written. Write without them, then set access with remote_run, " +
		"e.g. icacls 'C:\\path\\file' /setowner 'HOST\\user' or Get-Acl/Set-Acl."
)

// rcon is RCON's /run JSON; only rc matters here.
func runHint(goos, command string, rcon []byte, desktop bool) string {
	var result struct {
		RC *int `json:"rc"`
	}
	failed := json.Unmarshal(rcon, &result) == nil && result.RC != nil && *result.RC != 0
	switch goos {
	case "windows":
		if failed && hintBashisms.MatchString(command) {
			return hintWindowsShell
		}
		if desktop && hintGUILaunch.MatchString(command) {
			return hintSession0
		}
	case "linux":
		if failed && hintPowerShellisms.MatchString(command) {
			return hintLinuxShell
		}
	}
	return ""
}
