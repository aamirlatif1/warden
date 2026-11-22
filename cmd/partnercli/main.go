// Command partnercli plays the partner backend ("Shopr"): it owns a P-256
// key, signs private_key_jwt client assertions and calls partner-sts.
//
//	partnercli keygen    -key K -jwks J -kid shopr-1
//	partnercli assertion -key K -kid shopr-1 -client-id shopr -sts URL
//	partnercli token     -key K -kid shopr-1 -client-id shopr -sts URL [-scope S]
//
// assertion and token print only the JWT to stdout, for scripts.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/kms"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "assertion":
		err = assertionCmd(os.Args[2:])
	case "token":
		err = tokenCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "partnercli:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: partnercli keygen|assertion|token [flags]")
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyPath := fs.String("key", ".local/shopr.key.pem", "private key output (PKCS#8 PEM, 0600)")
	jwksPath := fs.String("jwks", ".local/shopr.jwks.json", "public JWK Set output (register this with the STS)")
	kid := fs.String("kid", "shopr-1", "key ID")
	force := fs.Bool("force", false, "overwrite an existing key")
	_ = fs.Parse(args)

	if _, err := os.Stat(*keyPath); err == nil && !*force {
		fmt.Fprintf(os.Stderr, "key %s exists; keeping it (use -force to replace)\n", *keyPath)
		key, err := loadKey(*keyPath)
		if err != nil {
			return err
		}
		return writeJWKS(*jwksPath, key, *kid)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	if err := kms.WritePrivateKeyPEM(*keyPath, key); err != nil {
		return err
	}
	return writeJWKS(*jwksPath, key, *kid)
}

func writeJWKS(path string, key *ecdsa.PrivateKey, kid string) error {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}}}
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "public JWKS written to %s (kid %s)\n", path, kid)
	return nil
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return kms.ParsePrivateKeyPEM(b)
}

type common struct {
	key, kid, clientID, sts *string
}

func commonFlags(fs *flag.FlagSet) common {
	return common{
		key:      fs.String("key", ".local/shopr.key.pem", "private key"),
		kid:      fs.String("kid", "shopr-1", "key ID"),
		clientID: fs.String("client-id", "shopr", "client_id"),
		sts:      fs.String("sts", "http://localhost:8083", "partner-sts base URL (discovery is fetched from it)"),
	}
}

type discovery struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
}

func discover(ctx context.Context, base string) (discovery, error) {
	var d discovery
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/.well-known/oauth-authorization-server", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("discovery: HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&d); err != nil {
		return d, err
	}
	if d.Issuer == "" || d.TokenEndpoint == "" {
		return d, errors.New("discovery: missing issuer or token_endpoint")
	}
	return d, nil
}

// signAssertion builds the RFC 7523 client assertion: iss = sub = client_id,
// aud = the STS issuer identifier (rfc7523bis), 60 s lifetime, random jti.
func signAssertion(key *ecdsa.PrivateKey, kid, clientID, aud string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		return "", err
	}
	var jti [16]byte
	_, _ = rand.Read(jti[:])
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
		"jti": hex.EncodeToString(jti[:]),
	})
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func assertionCmd(args []string) error {
	fs := flag.NewFlagSet("assertion", flag.ExitOnError)
	c := commonFlags(fs)
	_ = fs.Parse(args)
	key, err := loadKey(*c.key)
	if err != nil {
		return err
	}
	d, err := discover(context.Background(), *c.sts)
	if err != nil {
		return err
	}
	a, err := signAssertion(key, *c.kid, *c.clientID, d.Issuer)
	if err != nil {
		return err
	}
	fmt.Println(a)
	return nil
}

func tokenCmd(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	c := commonFlags(fs)
	scope := fs.String("scope", "quotes:write", "requested scope")
	_ = fs.Parse(args)
	key, err := loadKey(*c.key)
	if err != nil {
		return err
	}
	ctx := context.Background()
	d, err := discover(ctx, *c.sts)
	if err != nil {
		return err
	}
	a, err := signAssertion(key, *c.kid, *c.clientID, d.Issuer)
	if err != nil {
		return err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {clientauth.AssertionType},
		"client_assertion":      {a},
		"scope":                 {*scope},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return fmt.Errorf("token response: HTTP %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token: HTTP %d %s: %s", resp.StatusCode, body.Error, body.Description)
	}
	fmt.Println(body.AccessToken)
	return nil
}
