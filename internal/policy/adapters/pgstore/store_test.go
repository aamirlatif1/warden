package pgstore_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/policy/adapters/pgstore"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

// Integration tests against a real Postgres. Run with `make test-db`
// (needs `make up`). Skipped when WARDEN_TEST_DATABASE_URL is unset.
func open(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("WARDEN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("WARDEN_TEST_DATABASE_URL not set; run make test-db")
	}
	s, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

var ctx = context.Background()

// uid keeps tests independent on a shared database.
func uid(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := open(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestPolicies(t *testing.T) {
	s := open(t)
	holder := uid("sub")
	p1 := domain.Policy{ID: uid("pol"), HolderSubject: holder, Product: "travel", Status: "active"}
	p2 := domain.Policy{ID: uid("pol"), HolderSubject: uid("other"), Product: "phone", Status: "active"}
	for _, p := range []domain.Policy{p1, p2} {
		if err := s.UpsertPolicy(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.ListPoliciesByHolder(ctx, holder)
	if err != nil || len(got) != 1 || got[0].ID != p1.ID {
		t.Fatalf("ListPoliciesByHolder = %v, %v", got, err)
	}
	if _, err := s.GetPolicy(ctx, uid("missing")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing policy: err = %v", err)
	}
	updated, err := s.SetPayoutIBAN(ctx, p1.ID, "DE89370400440532013000")
	if err != nil || updated.PayoutIBAN != "DE89370400440532013000" {
		t.Fatalf("SetPayoutIBAN = %+v, %v", updated, err)
	}
	if _, err := s.SetPayoutIBAN(ctx, uid("missing"), "x"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetPayoutIBAN on missing: err = %v", err)
	}
}

func TestQuotesAndLimits(t *testing.T) {
	s := open(t)
	if err := s.SaveQuote(ctx, domain.Quote{ID: uid("q"), PartnerID: "shopr", Product: "phone", Premium: domain.Money{AmountMinor: 1200, Currency: "EUR"}}); err != nil {
		t.Fatal(err)
	}
	sub := uid("ben")
	if l, err := s.ApprovalLimit(ctx, sub); err != nil || l != 0 {
		t.Fatalf("no row: %d, %v", l, err)
	}
	if err := s.UpsertApprovalLimit(ctx, sub, 2_000_000); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertApprovalLimit(ctx, sub, 500_000); err != nil {
		t.Fatal(err)
	}
	if l, err := s.ApprovalLimit(ctx, sub); err != nil || l != 500_000 {
		t.Fatalf("limit = %d, %v", l, err)
	}
}

// Concurrent approvals of the same claim: the row lock serialises them,
// so exactly one succeeds and the others see ErrConflict.
//
// A barrier between read and write forces the transactions to overlap.
// Without FOR UPDATE every goroutine reads "open" before anyone writes and
// all of them approve. With the lock, later readers block on the row, the
// barrier times out, and they run one after another.
func TestConcurrentApprovalIsSerialised(t *testing.T) {
	s := open(t)
	c := domain.Claim{ID: uid("clm"), PolicyID: uid("pol"), Amount: domain.Money{AmountMinor: 100, Currency: "EUR"}, Status: domain.ClaimOpen}
	if err := s.UpsertClaim(ctx, c); err != nil {
		t.Fatal(err)
	}

	const n = 4
	var (
		mu      sync.Mutex
		arrived int
		allIn   = make(chan struct{})
	)
	barrier := func() {
		mu.Lock()
		arrived++
		if arrived == n {
			close(allIn)
		}
		mu.Unlock()
		select {
		case <-allIn:
		case <-time.After(300 * time.Millisecond):
		}
	}

	approve := func() error {
		return s.InTx(ctx, func(ctx context.Context) error {
			locked, err := s.GetClaimForUpdate(ctx, c.ID)
			if err != nil {
				return err
			}
			barrier()
			next, err := locked.Approve()
			if err != nil {
				return err
			}
			return s.SaveClaim(ctx, next)
		})
	}

	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { errs[i] = approve() })
	}
	wg.Wait()

	ok, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, domain.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflicts != n-1 {
		t.Fatalf("ok = %d, conflicts = %d; want 1 and %d (lost update: row not locked?)", ok, conflicts, n-1)
	}
	got, _ := s.GetClaim(ctx, c.ID)
	if got.Status != domain.ClaimApproved {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestTxRollsBack(t *testing.T) {
	s := open(t)
	p := domain.Policy{ID: uid("pol"), HolderSubject: "x", Product: "p", Status: "active"}
	if err := s.UpsertPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err := s.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.SetPayoutIBAN(ctx, p.ID, "DE89370400440532013000"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	got, _ := s.GetPolicy(ctx, p.ID)
	if got.PayoutIBAN != "" {
		t.Fatal("write survived a rolled-back transaction")
	}
}
