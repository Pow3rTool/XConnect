# XConnect — connection broker (data plane)

Where RCON clients register and talk. Holds the persistent **reverse-dial**
tunnels from every RCON and patches authorized Caller requests onto the target
RCON's tunnel. It is a **bounded stream relay** (an 87 GB ISO is rejected by
policy, not heroically streamed); the sole buffer is the explicitly bounded,
ephemeral agent-output capture described below.

## Role
- Terminates RCON mTLS tunnels — **mutually pinned** (anchor-not-leaf, ship + remember)
- **Multiplexed** (HTTP/2 or QUIC): one tunnel per RCON, many concurrent channels
- Holds **no signing authority** — the CA lives behind Orthanc (plane split by design, so popping the data plane can't mint RCON identities)
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
cd /nfs/pow3rtool/XConnect && /usr/local/go/bin/go build -o xconnect .
# identity (key/cert/ca-bundle) minted on the tower into ./etc :
#   (Orthanc) manage.py mint_system_identity --tenant 3lab --role xconnect --out /nfs/pow3rtool/XConnect/etc
./xconnect whoami                 # prints our SVID
./xconnect control hello          # proves the link + tenant scoping
./xconnect control allowlist      # ACTIVE node SVIDs for our tenant only
```
Flags: `--etc`, `--control-url` (default `https://127.0.0.1:8443`), `--server-id`,
`--broker-port`, `--web-addr`. See [`../ARCHITECTURE.md`](../ARCHITECTURE.md).
