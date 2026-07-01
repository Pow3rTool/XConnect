package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Identity is XConnect's own SPIFFE keypair plus the pinned trust anchor.
// XConnect holds only this — no CA, no signing key (the plane split).
type Identity struct {
	Cert   tls.Certificate
	CAPool *x509.CertPool // OUR anchor (root+intermediate); the system store is never consulted
}

func loadIdentity(etcDir, role string) (*Identity, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(etcDir, role+"-cert.pem"),
		filepath.Join(etcDir, role+"-key.pem"),
	)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	bundle, err := os.ReadFile(filepath.Join(etcDir, "ca-bundle.pem"))
	if err != nil {
		return nil, fmt.Errorf("read ca bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, fmt.Errorf("no certs found in ca-bundle.pem")
	}
	return &Identity{Cert: cert, CAPool: pool}, nil
}

// SpiffeID returns XConnect's own SVID (the first URI SAN of its leaf).
func (i *Identity) SpiffeID() (string, error) {
	leaf, err := x509.ParseCertificate(i.Cert.Certificate[0])
	if err != nil {
		return "", err
	}
	return spiffeID(leaf), nil
}

func spiffeID(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		return u.String()
	}
	return ""
}

// spkiFingerprint is the SHA-256 of the cert's SubjectPublicKeyInfo — the same
// durable key identity Orthanc keys enrollments and allow-list entries on.
func spkiFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// tenantOf pulls the tenant slug out of a SPIFFE id: the first path segment of
// spiffe://<trust-domain>/<tenant>/... (returns "" if there isn't one).
func tenantOf(svid string) string {
	u, err := url.Parse(svid)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
