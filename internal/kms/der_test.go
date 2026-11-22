package kms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func der(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Round trip against Go's own DER signer and verifier: the JOSE bytes split
// back into R and S must verify.
func TestDERToJOSERoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256([]byte("header.payload"))
	sawPadded := false
	for range 200 {
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 70 {
			sawPadded = true // DER length varies: 70, 71 or 72 bytes
		}
		jose, err := DERToJOSE(sig)
		if err != nil {
			t.Fatal(err)
		}
		if len(jose) != 64 {
			t.Fatalf("len = %d, want 64", len(jose))
		}
		r := new(big.Int).SetBytes(jose[:32])
		s := new(big.Int).SetBytes(jose[32:])
		if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
			t.Fatal("converted signature does not verify")
		}
	}
	if !sawPadded {
		t.Log("note: no variable-length DER seen in 200 samples")
	}
}

func TestDERToJOSEEdgeCases(t *testing.T) {
	top := new(big.Int).Lsh(big.NewInt(1), 255) // top bit set: DER adds 0x00
	small := big.NewInt(0x01ff)                 // 2 bytes: must be left-padded
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	t.Run("leading 0x00 stripped and short values padded", func(t *testing.T) {
		got, err := DERToJOSE(der(t, top, small))
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 64)
		top.FillBytes(want[:32])
		small.FillBytes(want[32:])
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x\nwant %x", got, want)
		}
		if got[0] != 0x80 || got[62] != 0x01 || got[63] != 0xff || got[32] != 0 {
			t.Fatalf("unexpected layout %x", got)
		}
	})

	t.Run("max 256-bit values", func(t *testing.T) {
		if _, err := DERToJOSE(der(t, max, max)); err != nil {
			t.Fatal(err)
		}
	})

	bad := map[string][]byte{
		"empty":                    nil,
		"not DER":                  []byte("not a signature"),
		"JOSE given twice":         bytes.Repeat([]byte{1}, 64),
		"trailing data":            append(der(t, small, small), 0x00),
		"R too long (P-384 sized)": der(t, new(big.Int).Lsh(big.NewInt(1), 300), small),
		"zero R":                   der(t, big.NewInt(0), small),
		"negative S":               der(t, small, big.NewInt(-5)),
	}
	for name, in := range bad {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := DERToJOSE(in); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}
