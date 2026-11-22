package tlsutil

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

type pki struct{ dir string }

func (p pki) f(name string) string { return filepath.Join(p.dir, name) }

// newPKI writes ca, server (policy-api), client "bff" and client "intruder"
// (same CA, not allowed), plus a second CA's client "rogue".
func newPKI(t *testing.T) pki {
	t.Helper()
	p := pki{dir: t.TempDir()}
	ca, err := NewDevCA("warden dev CA")
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(WriteFile(p.dir, "ca.pem", ca.PEM, false))
	for _, leaf := range []struct {
		cn     string
		server bool
	}{{"policy-api", true}, {"bff", false}, {"intruder", false}} {
		c, k, err := ca.Issue(leaf.cn, leaf.server)
		must(err)
		must(WriteFile(p.dir, leaf.cn+".pem", c, false))
		must(WriteFile(p.dir, leaf.cn+".key", k, true))
	}
	other, _ := NewDevCA("rogue CA")
	c, k, _ := other.Issue("bff", false) // right name, wrong CA
	must(WriteFile(p.dir, "rogue.pem", c, false))
	must(WriteFile(p.dir, "rogue.key", k, true))
	return p
}

func TestMTLS(t *testing.T) {
	p := newPKI(t)
	srvCfg, err := ServerMTLS(p.f("policy-api.pem"), p.f("policy-api.key"), p.f("ca.pem"), "spiffe://warden.local/bff")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	srv.TLS = srvCfg
	srv.StartTLS()
	defer srv.Close()

	call := func(cert, key string) error {
		cfg, err := ClientMTLS(p.f("ca.pem"), p.f(cert), p.f(key))
		if err != nil {
			return err
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := c.Get(srv.URL)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	if err := call("bff.pem", "bff.key"); err != nil {
		t.Fatalf("bff rejected: %v", err)
	}
	if err := call("intruder.pem", "intruder.key"); err == nil {
		t.Fatal("a client from our CA but not on the allow-list got in")
	}
	if err := call("rogue.pem", "rogue.key"); err == nil {
		t.Fatal("a client from another CA got in")
	}
	plain := &http.Client{Transport: &http.Transport{TLSClientConfig: mustClientNoCert(t, p)}}
	if _, err := plain.Get(srv.URL); err == nil {
		t.Fatal("a client without a certificate got in")
	}
}

func mustClientNoCert(t *testing.T, p pki) *tlsConfig {
	t.Helper()
	pool, err := loadPool(p.f("ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return &tlsConfig{RootCAs: pool, MinVersion: 0x0304}
}

type tlsConfig = tls.Config
