package app

import (
	"context"
	"log/slog"

	"github.com/aamirlatif1/warden/internal/authz"
)

// DeviceStore remembers devices that completed a login, and the country
// they last logged in from.
type DeviceStore interface {
	// LastCountry reports whether the device is known and its last country.
	LastCountry(ctx context.Context, deviceID string) (country string, known bool, err error)
	Remember(ctx context.Context, deviceID, country string) error
}

// LoginRisk applies the adaptive-authentication rule (authz.AssessLogin)
// before a login starts.
type LoginRisk struct {
	devices DeviceStore
	log     *slog.Logger
}

func NewLoginRisk(d DeviceStore, log *slog.Logger) *LoginRisk {
	return &LoginRisk{devices: d, log: log}
}

// ACRValues returns "gold" when the login must include a second factor,
// "" otherwise. A store error counts as an unknown device: fail towards
// the stronger login, never the weaker one.
func (r *LoginRisk) ACRValues(ctx context.Context, deviceID, country string) string {
	last, known, err := "", false, error(nil)
	if deviceID != "" {
		last, known, err = r.devices.LastCountry(ctx, deviceID)
		if err != nil {
			r.log.WarnContext(ctx, "device store unavailable; treating device as new", "err", err)
			known = false
		}
	}
	risk := authz.AssessLogin(authz.LoginSignals{DeviceKnown: known, Country: country, LastCountry: last})
	if !risk.StepUp {
		return ""
	}
	r.log.InfoContext(ctx, "adaptive step-up at login", "reasons", risk.Reasons)
	return "gold"
}

// Remember records the device after a successful login. A missing country
// keeps the previous one.
func (r *LoginRisk) Remember(ctx context.Context, deviceID, country string) error {
	if deviceID == "" {
		return nil
	}
	if country == "" {
		last, _, err := r.devices.LastCountry(ctx, deviceID)
		if err != nil {
			return err
		}
		country = last
	}
	return r.devices.Remember(ctx, deviceID, country)
}
