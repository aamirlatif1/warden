package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// randomToken returns 256 bits of randomness, base64url (43 chars).
func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// NewSessionID and NewCSRFToken are exported for the callback.
func NewSessionID() string { return randomToken() }
func NewCSRFToken() string { return randomToken() }

// pkceChallenge is S256(verifier) per RFC 7636 §4.2.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
