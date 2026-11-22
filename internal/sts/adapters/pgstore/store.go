// Package pgstore is partner-sts's partner registry in Postgres (GORM).
// It serves both the app (domain.Partner) and the client authenticator
// (clientauth.Client with parsed public keys).
package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/aamirlatif1/warden/internal/sts/clientauth"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

type Store struct{ db *gorm.DB }

func Open(dsn string) (*Store, error) {
	gl := logger.New(log.New(os.Stderr, "gorm ", log.LstdFlags), logger.Config{
		SlowThreshold: 200 * time.Millisecond, LogLevel: logger.Warn,
		IgnoreRecordNotFoundError: true, ParameterizedQueries: true,
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

func (s *Store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&partnerModel{})
}

// partnerModel lives in its own table: partner-sts shares the dev Postgres
// database with policy-api but owns only sts_* tables.
type partnerModel struct {
	ClientID      string `gorm:"primaryKey"`
	PartnerID     string `gorm:"not null"`
	Name          string `gorm:"not null"`
	Status        string `gorm:"not null"`
	AllowedScopes string `gorm:"not null"` // space-separated
	JWKS          string `gorm:"not null"` // public JWK Set JSON
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (partnerModel) TableName() string { return "sts_partners" }

func (m partnerModel) toDomain() domain.Partner {
	return domain.Partner{
		ClientID: m.ClientID, PartnerID: m.PartnerID, Name: m.Name,
		Status: domain.PartnerStatus(m.Status), AllowedScopes: strings.Fields(m.AllowedScopes),
		JWKS: []byte(m.JWKS),
	}
}

func (s *Store) get(ctx context.Context, clientID string) (partnerModel, error) {
	var m partnerModel
	err := s.db.WithContext(ctx).First(&m, "client_id = ?", clientID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return m, domain.ErrNotFound
	}
	return m, err
}

// Partner implements app.PartnerStore.
func (s *Store) Partner(ctx context.Context, clientID string) (domain.Partner, error) {
	m, err := s.get(ctx, clientID)
	if err != nil {
		return domain.Partner{}, err
	}
	return m.toDomain(), nil
}

// Client implements clientauth.ClientLookup. Only public signing keys with
// a kid are returned; anything else in the stored set is ignored.
func (s *Store) Client(ctx context.Context, clientID string) (clientauth.Client, error) {
	m, err := s.get(ctx, clientID)
	if errors.Is(err, domain.ErrNotFound) {
		return clientauth.Client{}, clientauth.ErrUnknownClient
	}
	if err != nil {
		return clientauth.Client{}, err
	}
	keys, err := ParsePublicJWKS([]byte(m.JWKS))
	if err != nil {
		return clientauth.Client{}, fmt.Errorf("client %s: %w", clientID, err)
	}
	return clientauth.Client{ID: m.ClientID, Keys: keys}, nil
}

// ParsePublicJWKS parses a JWK Set and keeps public signing keys with a kid.
// A set that contains private key material is rejected outright: it means
// the partner sent us their private key.
func ParsePublicJWKS(b []byte) ([]jose.JSONWebKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	var out []jose.JSONWebKey
	for _, k := range set.Keys {
		if !k.IsPublic() {
			return nil, errors.New("jwks contains private key material")
		}
		if k.KeyID == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, errors.New("jwks has no usable signing key")
	}
	return out, nil
}

// UpsertPartner registers or replaces a partner (cmd/sts-seed, tests). The
// JWKS is validated before it is stored.
func (s *Store) UpsertPartner(ctx context.Context, p domain.Partner) error {
	if _, err := ParsePublicJWKS(p.JWKS); err != nil {
		return err
	}
	m := partnerModel{
		ClientID: p.ClientID, PartnerID: p.PartnerID, Name: p.Name, Status: string(p.Status),
		AllowedScopes: strings.Join(p.AllowedScopes, " "), JWKS: string(p.JWKS),
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&m).Error
}
