package authz

// Adaptive authentication (REQUIREMENTS FR-3): a login from a device the
// BFF has not seen, or from a different country than last time on this
// device, must reach acr=gold (second factor). Signals are simulated: a
// device cookie and the X-Country header. Pure function, no I/O.

// RiskReason is a stable label, logged with the login.
type RiskReason string

const (
	RiskNewDevice  RiskReason = "new_device"
	RiskNewCountry RiskReason = "new_country"
)

// LoginSignals are what the BFF knows before the user authenticates.
type LoginSignals struct {
	DeviceKnown bool   // the device cookie maps to a device that logged in before
	Country     string // ISO 3166-1 alpha-2 from X-Country, "" if absent or invalid
	LastCountry string // country of the last successful login on this device, "" if none
}

// LoginRisk says whether the login must be stepped up, and why.
type LoginRisk struct {
	StepUp  bool
	Reasons []RiskReason
}

// AssessLogin applies the rule. A missing country on either side is not a
// change: the header is simulated and absent by default.
func AssessLogin(s LoginSignals) LoginRisk {
	var r LoginRisk
	if !s.DeviceKnown {
		r.Reasons = append(r.Reasons, RiskNewDevice)
	} else if s.Country != "" && s.LastCountry != "" && s.Country != s.LastCountry {
		r.Reasons = append(r.Reasons, RiskNewCountry)
	}
	r.StepUp = len(r.Reasons) > 0
	return r
}
