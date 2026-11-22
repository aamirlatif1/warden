package domain

import (
	"errors"
	"testing"
)

func TestPriceQuote(t *testing.T) {
	cases := []struct {
		in      Money
		want    int64
		wantErr bool
	}{
		{Money{100_000, "EUR"}, 1500, false}, // 1000.00 € → 15.00 €
		{Money{1, "EUR"}, 1, false},          // rounds up
		{Money{0, "EUR"}, 0, true},
		{Money{-5, "EUR"}, 0, true},
		{Money{100, "EURO"}, 0, true},
	}
	for _, tc := range cases {
		got, err := PriceQuote(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("PriceQuote(%v) err = %v", tc.in, err)
		}
		if err == nil && (got.AmountMinor != tc.want || got.Currency != tc.in.Currency) {
			t.Errorf("PriceQuote(%v) = %v, want %d", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeIBAN(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"DE89 3704 0044 0532 0130 00", "DE89370400440532013000", true},
		{"de89370400440532013000", "DE89370400440532013000", true},
		{"GB82WEST12345698765432", "GB82WEST12345698765432", true},
		{"DE89370400440532013001", "", false}, // bad checksum
		{"DE8937040044", "", false},           // too short
		{"1289370400440532013000", "", false}, // country not letters
		{"DE89-3704-0044-0532-0130-00", "", false},
	}
	for _, tc := range cases {
		got, err := NormalizeIBAN(tc.in)
		if tc.ok != (err == nil) || got != tc.want {
			t.Errorf("NormalizeIBAN(%q) = %q, %v", tc.in, got, err)
		}
	}
}

func TestMaskedIBAN(t *testing.T) {
	if got := (Policy{PayoutIBAN: "DE89370400440532013000"}).MaskedIBAN(); got != "******************3000" {
		t.Errorf("got %q", got)
	}
	if got := (Policy{}).MaskedIBAN(); got != "" {
		t.Errorf("empty IBAN masked to %q", got)
	}
}

func TestClaimApprove(t *testing.T) {
	c, err := Claim{ID: "c1", Status: ClaimOpen}.Approve()
	if err != nil || c.Status != ClaimApproved {
		t.Fatalf("got %v, %v", c, err)
	}
	if _, err := c.Approve(); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approve: err = %v, want ErrConflict", err)
	}
}
