// Command devpki creates the local mTLS material in deploy/pki (gitignored):
// a dev CA, policy-api's server certificate, and the BFF client
// certificates. Dev only: production would use a real PKI (Vault, ACM PCA,
// SPIFFE/SPIRE).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aamirlatif1/warden/internal/tlsutil"
)

func main() {
	dir := flag.String("out", "deploy/pki", "output directory")
	force := flag.Bool("force", false, "overwrite existing material")
	flag.Parse()
	if _, err := os.Stat(filepath.Join(*dir, "ca.pem")); err == nil && !*force {
		fmt.Printf("%s/ca.pem exists; keeping the dev PKI (use -force to recreate)\n", *dir)
		return
	}
	if err := run(*dir); err != nil {
		fmt.Fprintln(os.Stderr, "devpki:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	ca, err := tlsutil.NewDevCA("warden dev CA")
	if err != nil {
		return err
	}
	if err := tlsutil.WriteFile(dir, "ca.pem", ca.PEM, false); err != nil {
		return err
	}
	leaves := []struct {
		name   string
		server bool
	}{{"policy-api", true}, {"bff", false}}
	for _, l := range leaves {
		cert, key, err := ca.Issue(l.name, l.server)
		if err != nil {
			return err
		}
		if err := tlsutil.WriteFile(dir, l.name+".pem", cert, false); err != nil {
			return err
		}
		if err := tlsutil.WriteFile(dir, l.name+".key", key, true); err != nil {
			return err
		}
	}
	fmt.Printf("dev PKI written to %s: ca.pem, policy-api.{pem,key}, bff.{pem,key}\n", dir)
	return nil
}
