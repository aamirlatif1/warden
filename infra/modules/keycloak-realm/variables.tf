variable "realm_name" {
  description = "Name of the realm for policyholders and underwriters."
  type        = string
  default     = "insurance"
}

variable "keycloak_public_url" {
  description = "Browser-facing Keycloak base URL; the issuer is <url>/realms/<realm>."
  type        = string
}

variable "bff_base_url" {
  description = "Browser-facing base URL of the portal BFF."
  type        = string
}

variable "claims_app_base_url" {
  description = "Browser-facing base URL of the claims-app BFF instance (SSO proof)."
  type        = string
}

variable "bff_backchannel_base_url" {
  description = "Base URL Keycloak uses to reach the portal BFF for back-channel logout."
  type        = string
}

variable "claims_app_backchannel_base_url" {
  description = "Base URL Keycloak uses to reach claims-app for back-channel logout."
  type        = string
}

variable "access_token_lifespan" {
  description = "Access token lifetime (Go duration string, e.g. 5m)."
  type        = string
  default     = "5m"
}

variable "sso_session_idle_timeout" {
  description = "SSO session idle timeout."
  type        = string
  default     = "30m"
}

variable "sso_session_max_lifespan" {
  description = "SSO session absolute lifetime."
  type        = string
  default     = "10h"
}

variable "enable_test_client" {
  description = "Create the warden-test client-credentials client (local only)."
  type        = bool
  default     = false
}

variable "seed_users" {
  description = "Synthetic users to create, keyed by username. Dev environments only."
  type = map(object({
    first_name = string
    last_name  = string
    email      = string
    password   = string
    roles      = list(string)
    partner_id = string
  }))
  default   = {}
  sensitive = true
}
