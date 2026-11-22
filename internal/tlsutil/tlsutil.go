// Package tlsutil builds the mTLS configs for BFF → policy-api, and the dev
// PKI that issues their certificates.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
)

// ServerMTLS requires a client certificate signed by clientCA whose
// identity (CN or a DNS/URI SAN) is in allowed. TLS 1.3 only.
func ServerMTLS(certFile, keyFile, clientCAFile string, allowed ...string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(clientCAFile)
	if err != nil {
		return nil, err
	}
	if len(allowed) == 0 {
		return nil, errors.New("tlsutil: no allowed client identities")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		// Chain verification proves "signed by our CA"; this pins WHO.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tlsutil: no client certificate")
			}
			if id := identity(cs.PeerCertificates[0], allowed); id == "" {
				return fmt.Errorf("tlsutil: client %q not allowed", cs.PeerCertificates[0].Subject.CommonName)
			}
			return nil
		},
	}, nil
}

// ClientMTLS presents certFile and trusts only serverCA.
func ClientMTLS(serverCAFile, certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(serverCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool}, nil
}

// PeerIdentity returns the allowed identity of a verified client cert, or "".
func identity(c *x509.Certificate, allowed []string) string {
	ids := append([]string{c.Subject.CommonName}, c.DNSNames...)
	for _, u := range c.URIs {
		ids = append(ids, u.String())
	}
	for _, id := range ids {
		if id != "" && slices.Contains(allowed, id) {
			return id
		}
	}
	return ""
}

func loadPool(file string) (*x509.CertPool, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("tlsutil: no certificates in %s", file)
	}
	return pool, nil
}
