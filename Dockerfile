# XConnect data-plane broker — self-contained multi-stage build.
#   podman build -t xconnect-broker .
#
# Stage 1 compiles a STATIC binary (CGO_ENABLED=0 -> pure-Go net resolver), so the
# final image is FROM scratch: just the binary + CA roots. The broker is stateless
# (in-memory allow-list + ring-buffer audit shipped to Orthanc), so there's nothing
# to persist in the image.
#
# Runtime specifics handled by the Quadlet unit, NOT baked here (keeps the binary generic):
#   * binds tcp/3       -> run with CAP_NET_BIND_SERVICE (unprivileged user otherwise)
#   * identity dir      -> mount /opt/xconnect/etc ro  (--etc), cert/key/ca-bundle 0600
#   * RCON signed bins  -> mount /opt/xconnect/rcon-dist ro (--bootstrap-bin-dir)
#   * tenant/audience/control-url/auth-mode -> EnvironmentFile (source already reads env)
#   * egress to login.microsoftonline.com (JWKS) + Orthanc :8443 (mTLS) -> --network=host
FROM golang:1.26 AS build
WORKDIR /src
# module layer cached separately from source
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
# static, reproducible, stripped
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/xconnect .

FROM scratch
# TLS roots for the Entra JWKS fetch (the mTLS trust to Orthanc comes from the mounted ca-bundle.pem)
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/xconnect /xconnect
# non-root numeric uid (scratch has no /etc/passwd). The mounted identity dir must be
# readable by this uid — see the Quadlet unit's NB on cert ownership.
USER 10001:10001
EXPOSE 3 8780 8790
# args (--etc, --bootstrap-bin-dir, --heartbeat, the `serve` subcommand) are supplied
# by the Quadlet Exec= line so the image stays deploy-agnostic.
ENTRYPOINT ["/xconnect"]
