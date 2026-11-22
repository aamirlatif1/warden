// Package authn validates bearer tokens from a fixed set of trusted issuers
// and turns them into a normalised Principal.
//
// The hot path makes no network call: signing keys come from a cached
// KeySource (see package jwks) and revocation from an in-memory Denylist.
//
// Layout:
//
//	principal.go   Principal and context helpers
//	errors.go      Reason labels and the Error type (metric + drill contract)
//	profiles.go    IssuerProfile: per-issuer alg pin, audience rule, claim mapping
//	validator.go   Validator.Validate: the validation pipeline
//
// Driving adapters live in ginauth (HTTP middleware) and grpcauth (unary
// interceptor). Both share one *Validator.
package authn
