package main

import (
	"net"
	"net/http"
	"time"
)

// hardenedServe runs mux on addr with anti-slowloris timeouts and a header cap.
// ReadHeaderTimeout bounds slow-header attacks; request bodies are capped by
// limitBody. WriteTimeout is left at 0 so long, legitimate command-output relays
// (bounded by the RCON's own 1MB/150s caps) aren't severed mid-stream.
func hardenedServe(addr string, mux http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           limitBody(mux, 4<<20), // 4 MB request-body ceiling
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB of headers
	}
	return srv.ListenAndServe()
}

// limitBody wraps every request body in a MaxBytesReader so a handler that reads
// a declared-but-unbounded body can't be made to buffer the host out of memory.
func limitBody(next http.Handler, max int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackAddr reports whether a listen address binds only the loopback
// interface. Used to refuse exposing the UNAUTHENTICATED admin API off-host.
// An explicit host that resolves to a non-loopback IP (or a wildcard/empty host)
// is treated as non-loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":8770" / "0.0.0.0:8770" — binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a hostname we can't be sure is loopback
	}
	return ip.IsLoopback()
}
