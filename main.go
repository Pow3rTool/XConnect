// XConnect — Pow3rtool data-plane broker.
//
// Two listeners (not yet wired): a raw mTLS, cert-gated BROKER for RCON
// reverse-dial tunnels (default tcp/3), and a friendly HTTPS WEBSERVICE behind
// nginx for enroll/cert-distribution + Caller OAuth/OBO. Both are separate from
// the UP-link to the Orthanc tower, which is what this tracer-bullet exercises:
// XConnect dials the tower's mTLS control listener, authenticates with its
// tenant-scoped SPIFFE identity, and pulls its tenant's allow-list.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"
)

func main() {
	etc := flag.String("etc", "/nfs/pow3rtool/XConnect/etc", "identity dir (cert/key/ca-bundle)")
	controlURL := flag.String("control-url", envOr("XCONNECT_CONTROL_URL", "https://127.0.0.1:8443"), "Orthanc control listener")
	serverID := flag.String("server-id", envOr("XCONNECT_CONTROL_SERVER_ID", "spiffe://pow3rtool/system/orthanc-control"), "expected control-server SPIFFE id")
	brokerPort := flag.String("broker-port", "3", "RCON reverse-dial broker port (raw cert-gated mTLS)")
	webAddr := flag.String("web-addr", ":443", "friendly HTTPS webservice (behind nginx)")
	heartbeat := flag.Duration("heartbeat", 30*time.Second, "serve: control-link heartbeat interval")
	adminAddr := flag.String("admin-addr", "", "serve: unauthenticated admin/ops escape hatch — OFF by default. Set to a unix socket path (0600, e.g. /run/xconnect/admin.sock) or a loopback host:port to enable for live debugging")
	callerAddr := flag.String("caller-addr", "127.0.0.1:8780", "serve: Caller/MCP webservice (behind nginx)")
	bootstrapAddr := flag.String("bootstrap-addr", "127.0.0.1:8790", "serve: certless node-enroll ingress (behind nginx /bootstrap)")
	bootstrapBinDir := flag.String("bootstrap-bin-dir", "/nfs/pow3rtool/RCON/dist", "serve: dir of rcon-<os>-<arch> binaries to hand out at /bootstrap/binary")
	authMode := flag.String("auth-mode", envOr("XCONNECT_AUTH_MODE", "entra"), "serve: token validation mode (entra|dev)")
	audience := flag.String("audience", os.Getenv("XCONNECT_AUDIENCE"), "serve: expected token audience (env XCONNECT_AUDIENCE)")
	tenantID := flag.String("tenant-id", os.Getenv("AZURE_TENANT_ID"), "serve: Entra tenant id (env AZURE_TENANT_ID)")
	devSecret := flag.String("dev-secret", os.Getenv("XCONNECT_DEV_SECRET"), "serve: HS256 secret for auth-mode=dev (testing only)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	id, err := loadIdentity(*etc, "xconnect")
	if err != nil {
		die("identity: %v", err)
	}

	switch args[0] {
	case "whoami":
		svid, err := id.SpiffeID()
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("XConnect identity: %s\n", svid)

	case "control":
		c := newControlClient(id, *controlURL, *serverID)
		sub := "hello"
		if len(args) > 1 {
			sub = args[1]
		}
		switch sub {
		case "hello":
			out, err := c.call("/control/v1/hello", map[string]any{})
			report("hello", out, err)
		case "allowlist":
			out, err := c.call("/control/v1/allowlist", map[string]any{})
			report("allowlist", out, err)
		default:
			die("unknown control subcommand %q (hello|allowlist)", sub)
		}

	case "serve":
		svid, _ := id.SpiffeID()
		tenant := tenantOf(svid)
		c := newControlClient(id, *controlURL, *serverID)
		// This process's incarnation id: on restart it changes, so the tower clears
		// any "running" rows we left behind (they can't still be executing).
		c.instanceID = newID()
		fmt.Printf("XConnect serve — identity %s (tenant %s) instance %s\n", svid, tenant, c.instanceID)
		allow := NewAllowList()
		broker := &Broker{id: id, allow: allow, tenant: tenant, control: c}
		calls := NewCallLog(2000) // audit buffer, shipped on the heartbeat

		// Prime the allow-list before accepting tunnels (avoid an empty-list race).
		if t, nodes, err := c.fetchAllowList(); err != nil {
			fmt.Printf("warning: initial allow-list fetch failed: %v\n", err)
		} else {
			allow.Replace(t, nodes)
		}

		// Control-link heartbeat: refresh the allow-list, report live tunnels
		// (dashboard liveness + Call-log seed), keep last_seen fresh.
		go func() {
			for {
				d := time.Duration(float64(*heartbeat) * (0.7 + 0.6*rand.Float64()))
				time.Sleep(d)
				ts := time.Now().Format("15:04:05")
				if t, nodes, err := c.fetchAllowList(); err != nil {
					fmt.Printf("[%s] control: %v\n", ts, err)
				} else {
					if !allow.Replace(t, nodes) {
						fmt.Printf("[%s] control: allow-list came back EMPTY — retaining %d last-known-good (not applying)\n", ts, allow.Size())
					}
					broker.reconcile() // revoke-now: drop live tunnels that fell off the list
					live := broker.LiveTunnels()
					batch := calls.Drain() // ship buffered audit events with the report
					nudges, err := c.reportTunnels(live, batch)
					if err != nil {
						fmt.Printf("[%s] control: report failed: %v\n", ts, err)
						calls.Requeue(batch) // don't lose audit events on a transient blip
					}
					// Operator-requested updates (pull): nudge each flagged node.
					for _, svid := range nudges {
						fmt.Printf("[%s] control: operator update-nudge for %s\n", ts, svid)
						go broker.forceUpdate(svid)
					}
					fmt.Printf("[%s] control: tenant=%s allow-list=%d tunnels-live=%d\n",
						ts, t, len(nodes), len(live))
				}
			}
		}()

		// Low-latency audit shipper: flush buffered call events ~200ms after a
		// call (coalescing bursts) instead of waiting for the ~30s heartbeat, so
		// the Witchhunt log feels live. The heartbeat stays a backstop.
		go func() {
			retry := time.NewTicker(5 * time.Second) // catch a requeued backlog after a blip
			defer retry.Stop()
			for {
				select {
				case <-calls.Notify():
					time.Sleep(200 * time.Millisecond) // coalesce a burst into one ship
				case <-retry.C:
				}
				batch := calls.Drain()
				if len(batch) == 0 {
					continue
				}
				if err := c.shipCalls(batch); err != nil {
					fmt.Printf("[%s] calllog: ship failed (%d events requeued): %v\n",
						time.Now().Format("15:04:05"), len(batch), err)
					calls.Requeue(batch)
				}
			}
		}()

		// Fast revocation poll (unconditional): revocation removes a node from the
		// allow-list, but the live tunnel isn't killed until a reconcile. The
		// heartbeat reconciles every ~heartbeat (~20s); this tighter loop watches a
		// cheap revoked-count signal and reconciles IMMEDIATELY when it climbs —
		// bounding revoke→kill to a few seconds. The heartbeat stays the backstop.
		// Respects the plane split: XConnect polls; Orthanc never dials down.
		go func() {
			tick := time.NewTicker(3 * time.Second)
			defer tick.Stop()
			last := -1 // first poll just records the baseline (no reconcile on boot)
			fails := 0 // consecutive poll failures — so an outage isn't silent
			for range tick.C {
				n, err := c.revCount()
				if err != nil {
					// Transient — the heartbeat reconcile is the backstop — but a
					// SUSTAINED failure means the fast revoke path is dark, so make it
					// operator-visible (throttled: first failure + every ~minute).
					fails++
					if fails == 1 || fails%20 == 0 {
						fmt.Printf("[%s] revocation poll failing (%d consecutive): %v — heartbeat reconcile is the backstop\n",
							time.Now().Format("15:04:05"), fails, err)
					}
					continue
				}
				if fails > 0 {
					fmt.Printf("[%s] revocation poll recovered after %d failure(s)\n",
						time.Now().Format("15:04:05"), fails)
					fails = 0
				}
				if last >= 0 && n > last {
					ts := time.Now().Format("15:04:05")
					fmt.Printf("[%s] revocation detected (revoked %d→%d) — reconciling now\n", ts, last, n)
					if err := broker.refreshAndReconcile(); err != nil {
						fmt.Printf("[%s] fast-reconcile failed: %v\n", ts, err)
					}
				}
				last = n
			}
		}()

		if *adminAddr != "" {
			// Off by default: every admin function is otherwise covered (run/jobs/
			// read/edit/write by the authenticated Caller; renew/update/reconcile by
			// the auto sweeps + control-link nudges). Enable only for live debugging.
			fmt.Printf("WARNING: unauthenticated admin API enabled on %s — for debugging only\n", *adminAddr)
			go broker.ServeAdmin(*adminAddr)
		}
		go broker.renewSweep() // auto-renew node certs nearing expiry
		go (&Bootstrap{control: c, binDir: *bootstrapBinDir,
			publicURL: os.Getenv("XCONNECT_PUBLIC_BOOTSTRAP_URL")}).Serve(*bootstrapAddr)
		caller := &Caller{broker: broker, control: c, calls: calls,
			validate: newValidator(*authMode, *tenantID, *audience, *devSecret)}
		go caller.Serve(*callerAddr)
		_ = *webAddr // nginx fronts callerAddr as the XConnect vhost on :443
		die("broker: %v", broker.Listen(":"+*brokerPort))

	default:
		usage()
		os.Exit(2)
	}
}

func report(label string, out map[string]any, err error) {
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Printf("%s ->\n%s\n", label, b)
	if err != nil {
		die("%v", err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: xconnect [flags] <whoami|control [hello|allowlist]|serve>")
	flag.PrintDefaults()
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "xconnect: "+format+"\n", a...)
	os.Exit(1)
}

// envOr returns the env var if set, else the fallback — lets deployment-specific
// config (tenant/audience/control URL) come from the environment so the source
// carries no site-specific defaults.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
