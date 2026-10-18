# XConnect — connection broker (data plane)

Where RCON clients register and talk. Holds the persistent **reverse-dial**
tunnels from every RCON and patches authorized Caller requests onto the target
RCON's tunnel. It is a **bounded stream relay** (an 87 GB ISO is rejected by
policy, not heroically streamed); the sole buffer is the explicitly bounded,
ephemeral agent-output capture described below.

## Role
- Terminates RCON mTLS tunnels — **mutually pinned** (anchor-not-leaf, ship + remember)
- **Multiplexed** (HTTP/2 or QUIC): one tunnel per RCON, many concurrent channels
- Holds **no device-CA signing authority** — the CA lives behind Orthanc. The
  optional identity-login experiment uses a separate, explicitly configured
  signing key for its privately pinned local-account grants.
- **Propagates cancellation end-to-end** — Caller drops → close RCON stream → RCON reaps the process
- Per-channel/per-tunnel byte + rate caps; bulk transfer is a separate quota'd path

## Auth planes meet here
- RCON side: mTLS device identity (reverse-dialed, NAT-friendly)
- Caller side: OAuth + OBO (the acting principal) — never shares a credential type with the RCON side
- Every call carries **two identities**: which box (cert) + which principal (OBO) → both logged

## Agent-facing results and ephemeral output captures

The MCP bridge returns native MCP `structuredContent` for every tool call, with
the same compact JSON serialized as `TextContent` for older clients. XConnect
also decodes the nested RCON response for the bridge, so agents receive real
objects and status fields rather than JSON-escaped JSON strings.

`remote_run` keeps ordinary output inline. When stdout plus stderr exceeds
32 KiB—or the caller passes `capture_output=true`—Caller stores the complete
RCON-capped streams in RAM and returns 2,048-character previews plus a
`capture_id`. `read_command_output` can then inspect stdout or stderr using:

- `mode=page` with a zero-based character `offset`;
- `mode=tail` for the final bounded character window; or
- `mode=search` for line-oriented RE2 search with bounded context and matches.

A capture is deliberately not durable:

- IDs contain 128 random bits and reveal no host/path information.
- The ID is a locator, not a bearer capability. Reads require a fresh valid OBO
  token, exact tenant + human object ID + agent app ID ownership, and a current
  Orthanc authorization decision for the original verb.
- Captures expire after 10 minutes, disappear on process restart, and are
  limited to 4 MiB each, 16 entries/16 MiB per owner, and 128 entries/64 MiB
  globally with least-recently-used eviction.
- Raw capture bytes are never written to Orthanc/Postgres. Capture reads add a
  metadata-only Witchhunt event. The original command still follows the
  existing audit policy, which retains up to the first 64 KiB of its RCON
  response for operator forensics.

If a handle expires or the XConnect process restarts, rerun the source command.
This is intentional: durable command artifacts belong in an explicitly chosen
object store, not the control-plane database.

## Status
**Go service started** (`go.mod`, Go 1.26). The **control up-link to the Orthanc
tower is live and verified** — XConnect dials in with its tenant-scoped SPIFFE
identity, mutually pinned, and pulls its tenant's allow-list. Tenant isolation
and revocation proven. The two data-plane listeners are still stubs.

### Topology (decided)
- **Broker listener** — raw mTLS, cert-gated RCON reverse-dial tunnels (default
  `tcp/3`); not behind nginx. *(stub)*
- **Friendly HTTPS webservice** — `:443` behind nginx (own vhost): enrollment +
  cert distribution, and Caller/MCP OAuth+OBO ingress. *(stub)*
- **Control up-link** — mTLS HTTP/JSON to Orthanc's control listener; XConnect
  always dials out, tenant-scoped by its own SPIFFE cert. *(working)*

### Build & run
```bash
cd /opt/xconnect && /usr/local/go/bin/go build -o xconnect .
# identity (key/cert/ca-bundle) minted on the tower into ./etc :
#   (Orthanc) manage.py mint_system_identity --tenant example --role xconnect --out /etc/xconnect
./xconnect whoami                 # prints our SVID
./xconnect control hello          # proves the link + tenant scoping
./xconnect control allowlist      # ACTIVE node SVIDs for our tenant only
```
Flags: `--etc`, `--control-url` (default `https://127.0.0.1:8443`), `--server-id`,
`--broker-port`, `--web-addr`. See [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

The portable defaults are `/etc/xconnect` for identity and
`/var/lib/xconnect/binaries` for bootstrap artifacts. Existing installations
using other locations should keep explicit `--etc` and `--bootstrap-bin-dir`
arguments. Service examples assume a source checkout under `/opt/xconnect`.


### Windows console recovery and locking

Start with `desktop_status(node)`. It reads session IDs/SIDs, lock and connection
state, console placement, human pause, and backend readiness without capturing
pixels, starting a worker, moving a session or clearing a pause. It works during
a held interaction. Older nodes return `status_supported=false`; their existing
advertised desktop operations remain available. An RCON update never installs
or enables an LSA package.

`desktop_login(node)` uses only the authenticated caller's protected mapping.
The tool has no username, SID, credentials, force, or session-selection fields.
Phase one supports only a separately installed and privately pinned test backend.
A single existing active, unlocked session with the mapped SID is reused. A locked or
disconnected session is reported for explicit handling; another user's session
is never logged off. A cold sign-in requires an empty console, a ready backend,
an available signer, fresh caller authorization and no human pause. Identity
unlock is **not implemented**. Locking that session preserves apps but returning
to it currently requires human authentication.

The broker reads `XCONNECT_DESKTOP_IDENTITY_CONFIG`, a protected JSON file with
`key_file` and `mappings` (`node`, `tenant`, `principal`, `app`, `sid`). This first
version accepts only the privately pinned node, complete SPIFFE URI and SID.
Ordinary public builds have no pins and keep identity login disabled. The default
container build also excludes locally generated identity pins. Generate
the ignored build file using RCON `windows/lsa/setup-key.py --xconnect-dir`
with the same private deployment configuration used for the native verifier,
then build the private broker directly with Go. Mappings bind stable Entra IDs,
never UPN-derived usernames. The RSA-2048 private key must be a
mode-0600 file readable only by the broker account; it must match the verifier
already installed on the privately configured test host. No user password or
refresh token is retained.
Removing the mapping/key prevents future grants. The existing Orthanc `full`
grant remains required; this is not a new fine-grained node authorization system.

Sign-in grants are generated inside the broker, bound to the mapped principal,
node, SID, console, package boot challenge and one-use nonce, and expire in 45 s.
They travel only in the dedicated reverse-tunnel request and the native helper's
stdin, then through its SYSTEM-only LogonUI pipe. Challenges, grants and keys
are absent from model results and audit output. A transport timeout is an unknown
outcome: inspect status before retrying. General root/SYSTEM shell access remains
administrative access; narrowing this tool alone does not restrict such callers.

Use the existing session for personal co-working. Machine recovery is a separate
authorized mode, never a silent fallback or impersonation of the caller.

On an explicitly opted-in Windows node (`rcon.exe recovery-enable` as SYSTEM),
`desktop_recover(node)` creates the dedicated standard-user console session when
nobody is logged on, or unlocks its own existing locked console while preserving
the logon session and running applications. Human sessions, even disconnected ones, block recovery.
Credentials are generated and consumed locally; the API has no password field.
Observe after sign-in, then use `desktop_launch(..., wait=false)` for persistent
GUI applications. `wait=true` runs bounded commands and terminates their child
process tree when the call completes.

`desktop_lock(node, session_id=0)` preserves running applications and verifies
Windows reports the selected session locked. Session selection, full caller
authorization, human pause, and held-interaction exclusion still apply. Release
held input before locking. An already locked session returns success. Use `desktop_recover` to resume only the RCON-owned locked console; it generates
a fresh transient password for each unlock. Human sessions block that path.
A human can sign into their own account. After enabling
new tools on the MCP server, reconnect clients that cache the tool catalog.
See RCON/WINDOWS.md for opt-in, credential lifetime, logging and rollback.
