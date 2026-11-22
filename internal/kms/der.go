// Package kms holds the signing adapters for partner-sts: an AWS KMS
// signer and a local file signer. Both produce JOSE ES256 signatures.
package kms

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// p256Size is the byte length of R and S for P-256 (ES256).
const p256Size = 32

// DERToJOSE converts an ASN.1 DER ECDSA signature, as AWS KMS (and Go's
// ecdsa.SignASN1) returns it, into the JOSE format JWS requires (RFC 7518
// §3.4): R and S as fixed-length big-endian integers, concatenated.
//
//	DER:  30 len | 02 lenR R... | 02 lenS S...   (70–72 bytes, variable)
//	JOSE: R (32 bytes, left-padded) || S (32 bytes, left-padded) = 64 bytes
//
// The variable length comes from DER INTEGER rules: an integer whose top
// bit is set gets a leading 0x00 (so it stays positive), and leading zero
// bytes are otherwise stripped. A JWT library given DER instead of R||S
// rejects every token. That is the classic KMS-signs-JWT gotcha.
func DERToJOSE(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("ecdsa signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("ecdsa signature: trailing data after DER sequence")
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("ecdsa signature: R and S must be positive")
	}
	if sig.R.BitLen() > p256Size*8 || sig.S.BitLen() > p256Size*8 {
		return nil, errors.New("ecdsa signature: R or S longer than 32 bytes (not P-256)")
	}
	out := make([]byte, 2*p256Size)
	sig.R.FillBytes(out[:p256Size])
	sig.S.FillBytes(out[p256Size:])
	return out, nil
}
