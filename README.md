# XConnect — connection broker (data plane)

Where RCON clients register and talk. Holds the persistent **reverse-dial**
tunnels from every RCON and patches authorized Caller requests onto the target
RCON's tunnel. A **bounded stream relay — never a buffer** (an 87 GB ISO is
rejected by policy, not heroically streamed).

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
