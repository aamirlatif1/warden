// Package redisstore keeps BFF sessions, login transactions and refresh
// locks in Redis. Session and transaction records are encrypted with
// AES-256-GCM, and keys are a hash of the cookie value: a Redis dump
// yields neither usable tokens nor usable cookies.
package redisstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Sealer encrypts records. The AAD is the Redis key, so a ciphertext
// copied under another key (another session) does not decrypt.
type Sealer struct{ aead cipher.AEAD }

// NewSealer takes a 32-byte key (AES-256).
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("session key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

func (s *Sealer) seal(v any, aad string) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

var errOpen = errors.New("redisstore: record does not decrypt")

func (s *Sealer) open(b []byte, aad string, v any) error {
	n := s.aead.NonceSize()
	if len(b) < n {
		return errOpen
	}
	plain, err := s.aead.Open(nil, b[:n], b[n:], []byte(aad))
	if err != nil {
		return errOpen
	}
	return json.Unmarshal(plain, v)
}

// hashID maps a cookie value to a Redis key part.
func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
