// Package pgstore is the Postgres (GORM) driven adapter for policy-api's
// stores. GORM models stay in this package and are mapped to domain types;
// *gorm.DB never leaves it. Transactions reach the app through InTx, which
// carries the transaction in the context.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/aamirlatif1/warden/internal/policy/domain"
)

type Store struct {
	db *gorm.DB
}

// Open connects to Postgres. SQL is logged only when slow or failing, and
// always with placeholders, never with values (IBANs, subjects).
func Open(dsn string) (*Store, error) {
	gl := logger.New(log.New(os.Stderr, "gorm ", log.LstdFlags), logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gl, TranslateError: true})
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Migrate creates or updates the schema. Dev convenience; production would
// use versioned migrations.
func (s *Store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&policyModel{}, &claimModel{}, &quoteModel{}, &approvalLimitModel{})
}

// ---- models ----

type policyModel struct {
	ID            string `gorm:"primaryKey"`
	HolderSubject string `gorm:"not null;index"`
	Product       string `gorm:"not null"`
	Status        string `gorm:"not null"`
	PayoutIBAN    string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (policyModel) TableName() string { return "policies" }

type claimModel struct {
	ID          string `gorm:"primaryKey"`
	PolicyID    string `gorm:"not null;index"`
	AmountMinor int64  `gorm:"not null"`
	Currency    string `gorm:"not null;size:3"`
	Status      string `gorm:"not null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (claimModel) TableName() string { return "claims" }

type quoteModel struct {
	ID           string `gorm:"primaryKey"`
	PartnerID    string `gorm:"not null;index"`
	Product      string `gorm:"not null"`
	PremiumMinor int64  `gorm:"not null"`
	Currency     string `gorm:"not null;size:3"`
	CreatedAt    time.Time
}

func (quoteModel) TableName() string { return "quotes" }

// approvalLimitModel is the ABAC attribute for ApproveClaim, owned by the
// claims domain rather than the IdP.
type approvalLimitModel struct {
	Subject    string `gorm:"primaryKey"`
	LimitMinor int64  `gorm:"not null"`
	UpdatedAt  time.Time
}

func (approvalLimitModel) TableName() string { return "approval_limits" }

func (m policyModel) toDomain() domain.Policy {
	return domain.Policy{ID: m.ID, HolderSubject: m.HolderSubject, Product: m.Product, Status: m.Status, PayoutIBAN: m.PayoutIBAN}
}

func (m claimModel) toDomain() domain.Claim {
	return domain.Claim{ID: m.ID, PolicyID: m.PolicyID, Amount: domain.Money{AmountMinor: m.AmountMinor, Currency: m.Currency}, Status: domain.ClaimStatus(m.Status)}
}

// ---- transactions ----

type txKey struct{}

// conn returns the transaction in ctx, or the pool.
func (s *Store) conn(ctx context.Context) *gorm.DB {
	if tx, ok := ctx.Value(txKey{}).(*gorm.DB); ok {
		return tx
	}
	return s.db.WithContext(ctx)
}

func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return s.conn(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(context.WithValue(ctx, txKey{}, tx))
	})
}

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrNotFound
	}
	return err
}

// ---- PolicyStore ----

func (s *Store) ListPoliciesByHolder(ctx context.Context, subject string) ([]domain.Policy, error) {
	var ms []policyModel
	if err := s.conn(ctx).Where("holder_subject = ?", subject).Order("id").Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Policy, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.toDomain())
	}
	return out, nil
}

func (s *Store) GetPolicy(ctx context.Context, id string) (domain.Policy, error) {
	var m policyModel
	if err := s.conn(ctx).First(&m, "id = ?", id).Error; err != nil {
		return domain.Policy{}, notFound(err)
	}
	return m.toDomain(), nil
}

func (s *Store) SetPayoutIBAN(ctx context.Context, policyID, iban string) (domain.Policy, error) {
	res := s.conn(ctx).Model(&policyModel{}).Where("id = ?", policyID).Update("payout_iban", iban)
	if res.Error != nil {
		return domain.Policy{}, res.Error
	}
	if res.RowsAffected == 0 {
		return domain.Policy{}, domain.ErrNotFound
	}
	return s.GetPolicy(ctx, policyID)
}

// ---- QuoteStore ----

func (s *Store) SaveQuote(ctx context.Context, q domain.Quote) error {
	return s.conn(ctx).Create(&quoteModel{
		ID: q.ID, PartnerID: q.PartnerID, Product: q.Product,
		PremiumMinor: q.Premium.AmountMinor, Currency: q.Premium.Currency, CreatedAt: q.CreatedAt,
	}).Error
}

// ---- ClaimStore ----

func (s *Store) GetClaim(ctx context.Context, id string) (domain.Claim, error) {
	var m claimModel
	if err := s.conn(ctx).First(&m, "id = ?", id).Error; err != nil {
		return domain.Claim{}, notFound(err)
	}
	return m.toDomain(), nil
}

// GetClaimForUpdate takes a row lock (SELECT ... FOR UPDATE). Call it
// inside InTx; outside a transaction the lock ends with the statement.
func (s *Store) GetClaimForUpdate(ctx context.Context, id string) (domain.Claim, error) {
	var m claimModel
	if err := s.conn(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).First(&m, "id = ?", id).Error; err != nil {
		return domain.Claim{}, notFound(err)
	}
	return m.toDomain(), nil
}

func (s *Store) SaveClaim(ctx context.Context, c domain.Claim) error {
	res := s.conn(ctx).Model(&claimModel{}).Where("id = ?", c.ID).Update("status", string(c.Status))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// ---- ApprovalLimits ----

func (s *Store) ApprovalLimit(ctx context.Context, subject string) (int64, error) {
	var m approvalLimitModel
	err := s.conn(ctx).First(&m, "subject = ?", subject).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return m.LimitMinor, nil
}

// ---- seeding (cmd/policy-seed, tests) ----

// UpsertPolicy creates or fully replaces a policy.
func (s *Store) UpsertPolicy(ctx context.Context, p domain.Policy) error {
	m := policyModel{ID: p.ID, HolderSubject: p.HolderSubject, Product: p.Product, Status: p.Status, PayoutIBAN: p.PayoutIBAN}
	return s.conn(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&m).Error
}

// UpsertClaim creates or fully replaces a claim (resets its status).
func (s *Store) UpsertClaim(ctx context.Context, c domain.Claim) error {
	m := claimModel{ID: c.ID, PolicyID: c.PolicyID, AmountMinor: c.Amount.AmountMinor, Currency: c.Amount.Currency, Status: string(c.Status)}
	return s.conn(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&m).Error
}

func (s *Store) UpsertApprovalLimit(ctx context.Context, subject string, limitMinor int64) error {
	m := approvalLimitModel{Subject: subject, LimitMinor: limitMinor}
	return s.conn(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&m).Error
}
