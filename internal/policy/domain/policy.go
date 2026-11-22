// Package domain holds policy-api's entities and rules. Pure Go: no
// transport, storage or token imports.
package domain

import (
	"errors"
	"math/big"
	"strings"
	"time"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrConflict        = errors.New("conflict")
)

// Money is an amount in minor units (cents).
type Money struct {
	AmountMinor int64
	Currency    string
}

type Quote struct {
	ID        string
	PartnerID string
	Product   string
	Premium   Money
	CreatedAt time.Time
}

// QuoteRateBasisPoints is the demo premium: 1.5 % of the insured value.
const QuoteRateBasisPoints = 150

// PriceQuote returns the premium for an insured value, rounded up to the
// next cent.
func PriceQuote(insured Money) (Money, error) {
	if insured.AmountMinor <= 0 || len(insured.Currency) != 3 {
		return Money{}, ErrInvalidArgument
	}
	premium := (insured.AmountMinor*QuoteRateBasisPoints + 9999) / 10000
	return Money{AmountMinor: premium, Currency: insured.Currency}, nil
}

type Policy struct {
	ID            string
	HolderSubject string // Keycloak sub of the policyholder
	Product       string
	Status        string
	PayoutIBAN    string
}

// MaskedIBAN returns the IBAN with all but the last four characters hidden.
func (p Policy) MaskedIBAN() string {
	if len(p.PayoutIBAN) <= 4 {
		return strings.Repeat("*", len(p.PayoutIBAN))
	}
	return strings.Repeat("*", len(p.PayoutIBAN)-4) + p.PayoutIBAN[len(p.PayoutIBAN)-4:]
}

// NormalizeIBAN strips spaces, upper-cases, and checks length and the
// ISO 13616 mod-97 checksum.
func NormalizeIBAN(s string) (string, error) {
	iban := strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(iban) < 15 || len(iban) > 34 {
		return "", ErrInvalidArgument
	}
	for i, r := range iban {
		isLetter := r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		if (i < 2 && !isLetter) || (i >= 2 && i < 4 && !isDigit) || (!isLetter && !isDigit) {
			return "", ErrInvalidArgument
		}
	}
	var digits strings.Builder
	for _, r := range iban[4:] + iban[:4] {
		if r >= 'A' && r <= 'Z' {
			digits.WriteString(big.NewInt(int64(r - 'A' + 10)).String())
		} else {
			digits.WriteRune(r)
		}
	}
	n, _ := new(big.Int).SetString(digits.String(), 10)
	if new(big.Int).Mod(n, big.NewInt(97)).Int64() != 1 {
		return "", ErrInvalidArgument
	}
	return iban, nil
}

type ClaimStatus string

const (
	ClaimOpen     ClaimStatus = "open"
	ClaimApproved ClaimStatus = "approved"
)

type Claim struct {
	ID       string
	PolicyID string
	Amount   Money
	Status   ClaimStatus
}

// Approve moves an open claim to approved.
func (c Claim) Approve() (Claim, error) {
	if c.Status != ClaimOpen {
		return Claim{}, ErrConflict
	}
	c.Status = ClaimApproved
	return c, nil
}
