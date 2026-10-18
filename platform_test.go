package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsRuntimeInventoryAndHeartbeat(t *testing.T) {
	b := &Broker{allow: &AllowList{}}
	svid := "spiffe://pow3rtool/lab/node/test-windows"
	b.tunnels.Store(svid, nil)
	b.recordVersion(svid, `HTTP 200 {"version":"win-lab","goos":"windows","goarch":"amd64","shell":"powershell","os_version":"Windows 10.0 build 19045","protocol":1,"capabilities":{"self_update":false}}`)
	report := b.LiveTunnels()
	if len(report) != 1 || report[0]["goos"] != "windows" || report[0]["self_update_supported"] != false {
		t.Fatalf("report: %#v", report)
	}
	hosts := b.LiveHosts()
	if len(hosts) != 1 || hosts[0].GOOS != "windows" || hosts[0].Shell != "powershell" || hosts[0].OSVersion == "" {
		t.Fatalf("hosts: %#v", hosts)
	}
	// Explicitly unsupported updates must return before touching the control client.
	b.maybeUpdate(svid, `{"goos":"windows","capabilities":{"self_update":false}}`)
}

func TestLegacyRuntimeDoesNotInventPlatform(t *testing.T) {
	b := &Broker{}
	b.tunnels.Store("old", nil)
	b.recordVersion("old", `{"version":"legacy","goarch":"amd64"}`)
	report := b.LiveTunnels()[0]
	if report["goos"] != "" {
		t.Fatalf("invented OS: %#v", report)
	}
	if _, exists := report["self_update_supported"]; exists {
		t.Fatal("invented capability")
	}
}

func TestBootstrapWindowsExecutable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rcon-windows-amd64.exe"), []byte("MZtest"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &Bootstrap{binDir: dir}
	w := httptest.NewRecorder()
	b.binary(w, httptest.NewRequest("GET", "/bootstrap/binary?os=windows&arch=amd64", nil))
	if w.Code != http.StatusOK || w.Body.String() != "MZtest" || w.Header().Get("Content-Disposition") != "attachment; filename=rcon.exe" {
		t.Fatalf("response: %d %#v %q", w.Code, w.Header(), w.Body.String())
	}
	w = httptest.NewRecorder()
	b.binary(w, httptest.NewRequest("GET", "/bootstrap/binary?os=../../etc&arch=amd64", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("traversal accepted: %d", w.Code)
	}
}

func TestBootstrapPlatformParametersStayConfined(t *testing.T) {
	b := &Bootstrap{binDir: t.TempDir()}
	for _, query := range []string{
		"os=windows&arch=../../etc/passwd",
		"os=windows&arch=amd64%5c..%5csecret",
		"os=windows%2f..&arch=amd64",
		"os=windows%0d%0aX-Injected:yes&arch=amd64",
	} {
		w := httptest.NewRecorder()
		b.binary(w, httptest.NewRequest("GET", "/bootstrap/binary?"+query, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("query %q: got %d, want 400", query, w.Code)
		}
	}
}

func TestBootstrapLinuxFilenameUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rcon-linux-amd64"), []byte("linux-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	(&Bootstrap{binDir: dir}).binary(w, httptest.NewRequest("GET", "/bootstrap/binary", nil))
	if w.Code != http.StatusOK || w.Body.String() != "linux-test" || w.Header().Get("Content-Disposition") != "attachment; filename=rcon" {
		t.Fatalf("response: %d %#v %q", w.Code, w.Header(), w.Body.String())
	}
}
