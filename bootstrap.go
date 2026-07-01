package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

// Bootstrap is the certless, join-token-gated ingress a FRESH node hits before
// it has any identity. It relays enrollment up to Orthanc over the control link,
// so a node only ever talks to XConnect (never Orthanc directly). nginx fronts
// it on the XConnect ingress vhost at /bootstrap/*. The join token is the credential
// (validated by Orthanc, not here); TLS is terminated by nginx. This door does
// NOT require (or accept) a client cert — that's the whole point.
type Bootstrap struct {
	control   *ControlClient
	binDir    string // dir holding rcon-<os>-<arch> binaries to serve
	publicURL string // configured public base URL (XCONNECT_PUBLIC_BOOTSTRAP_URL); preferred over the request Host
}

var archTok = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)

// hostTok bounds an acceptable public Host (DNS name + optional port). Anything
// outside this set is rejected so a spoofed Host can never inject shell into the
// generated install.sh — which is piped to `sh` and runs as ROOT on the target.
var hostTok = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)

func (b *Bootstrap) Serve(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /bootstrap/enroll", b.enroll)
	mux.HandleFunc("GET /bootstrap/cert", b.cert)
	mux.HandleFunc("GET /bootstrap/binary", b.binary)
	mux.HandleFunc("GET /bootstrap/install.sh", b.installScript)
	log.Printf("bootstrap: certless enroll ingress on %s (/bootstrap/enroll, /bootstrap/cert)", addr)
	if err := hardenedServe(addr, mux); err != nil {
		log.Printf("bootstrap: %v", err)
	}
}

// enroll: {join_token, csr, name} -> relayed to Orthanc -> {state:pending, enrollment_id, spiffe_id}.
func (b *Bootstrap) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JoinToken string `json:"join_token"`
		CSR       string `json:"csr"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		bootJSON(w, 400, map[string]any{"error": "body must be JSON {join_token, csr, name}"})
		return
	}
	if req.JoinToken == "" || req.CSR == "" {
		bootJSON(w, 400, map[string]any{"error": "join_token and csr are required"})
		return
	}
	out, err := b.control.enroll(req.CSR, req.JoinToken, req.Name)
	if err != nil {
		// out may carry Orthanc's structured error (bad/expired/exhausted token).
		bootJSON(w, 400, orErr(out, err))
		return
	}
	bootJSON(w, 200, out)
}

// cert: ?id=<enrollment_id> -> relayed poll -> {state, certificate+trust_bundle once ACTIVE}.
func (b *Bootstrap) cert(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		bootJSON(w, 400, map[string]any{"error": "query param 'id' (enrollment_id) required"})
		return
	}
	out, err := b.control.enrollStatus(id)
	if err != nil {
		bootJSON(w, 404, orErr(out, err))
		return
	}
	bootJSON(w, 200, out)
}

// binary serves the static rcon agent for ?os=&arch= (defaults linux/amd64).
// Not secret (the agent binary); enrollment+approval+signing are the real gates.
func (b *Bootstrap) binary(w http.ResponseWriter, r *http.Request) {
	goos := r.URL.Query().Get("os")
	if goos == "" {
		goos = "linux"
	}
	goarch := r.URL.Query().Get("arch")
	if goarch == "" {
		goarch = "amd64"
	}
	if !archTok.MatchString(goos) || !archTok.MatchString(goarch) {
		bootJSON(w, 400, map[string]any{"error": "bad os/arch"})
		return
	}
	path := filepath.Join(b.binDir, fmt.Sprintf("rcon-%s-%s", goos, goarch))
	f, err := os.Open(path)
	if err != nil {
		bootJSON(w, 404, map[string]any{"error": fmt.Sprintf("no binary for %s/%s", goos, goarch)})
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=rcon")
	_, _ = io.Copy(w, f)
}

// installScript emits a one-liner installer: detect arch, pull the binary, drop
// it at /usr/local/bin/rcon. If RCON_JOIN_TOKEN is present in the caller's env it
// goes the whole way — `rcon install` configures + starts the (non-blocking)
// systemd service so the box self-enrolls and waits for approval without a
// foreground CLI. The token is read from the ENV, never the URL, so it never
// lands in nginx access logs.
//
// Fleet one-liner (token via env, not URL):
//
//	curl -fsSk https://<fqdn>/bootstrap/install.sh | RCON_JOIN_TOKEN=pjt_… sh
func (b *Bootstrap) installScript(w http.ResponseWriter, r *http.Request) {
	// Resolve the public base URL the root-run installer fetches from. Prefer the
	// explicitly CONFIGURED url (XCONNECT_PUBLIC_BOOTSTRAP_URL); only fall back to
	// the request Host if it passes a strict hostname check. An attacker who can
	// spoof Host must never be able to inject shell into a script piped to `sh`
	// as root (Crit: Host-reflected command injection).
	xc := b.publicURL
	if xc == "" {
		if !hostTok.MatchString(r.Host) {
			bootJSON(w, 400, map[string]any{
				"error": "cannot determine a safe public host from the request; set XCONNECT_PUBLIC_BOOTSTRAP_URL"})
			return
		}
		xc = "https://" + r.Host
	}
	// Single-quote the (already validated) URL in the emitted script so the shell
	// performs NO expansion on it — defense in depth atop the hostname allow-list.
	// TLS is verified (no -k): the bootstrap vhost has real public TLS, so an
	// on-path attacker can't substitute the installer, binary, or trust bundle.
	script := "#!/bin/sh\n" +
		"set -eu\n" +
		"XC='" + xc + "'\n" +
		`case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac
echo "fetching rcon (linux/$ARCH)…"
curl -fsS "$XC/bootstrap/binary?os=linux&arch=$ARCH" -o /usr/local/bin/rcon
chmod 0755 /usr/local/bin/rcon
mkdir -p /etc/rcon
echo "installed /usr/local/bin/rcon ($(/usr/local/bin/rcon --version 2>/dev/null || echo v?))"
if [ -n "${RCON_JOIN_TOKEN:-}" ]; then
  echo "enrolling as service (non-blocking; will wait for operator approval)…"
  # Forward an out-of-band CA pin if the operator supplied one (RCON_CA_PIN) —
  # defeats an enrollment-time MITM even when the origin TLS is self-signed.
  if [ -n "${RCON_CA_PIN:-}" ]; then
    /usr/local/bin/rcon install --token "$RCON_JOIN_TOKEN" --xconnect "$XC" --name "${RCON_NAME:-$(hostname)}" --ca-pin "$RCON_CA_PIN"
  else
    /usr/local/bin/rcon install --token "$RCON_JOIN_TOKEN" --xconnect "$XC" --name "${RCON_NAME:-$(hostname)}"
  fi
else
  echo "binary installed. To enroll the whole way, re-run with a token in the env:"
  echo "  curl -fsS $XC/bootstrap/install.sh | RCON_JOIN_TOKEN=pjt_… sh"
  echo "or interactively: rcon enroll --token <JOIN_TOKEN> --xconnect $XC --etc /etc/rcon --name <name>"
fi
`
	w.Header().Set("Content-Type", "text/x-shellscript")
	_, _ = io.WriteString(w, script)
}

func orErr(out map[string]any, err error) map[string]any {
	if out != nil {
		if _, ok := out["error"]; ok {
			return out
		}
	}
	return map[string]any{"error": err.Error()}
}

func bootJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
