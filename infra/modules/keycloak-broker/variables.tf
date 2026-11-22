variable "realm" {
  description = "The insurer's realm, where Nordbank is added as an identity provider."
  type        = string
}

variable "keycloak_public_url" {
  description = "Browser-facing Keycloak base URL (both realms live on it locally)."
  type        = string
}

variable "bank_realm" {
  description = "Realm that simulates the bank's SAML IdP."
  type        = string
  default     = "nordbank"
}

variable "alias" {
  description = "Identity provider alias in the insurer's realm; the BFF sends it as kc_idp_hint."
  type        = string
  default     = "nordbank"
}

variable "partner_id" {
  description = "Tenant stamped on every brokered account."
  type        = string
  default     = "nordbank"
}

variable "bank_users" {
  description = "Synthetic bank customers, keyed by username. Dev environments only."
  type = map(object({
    first_name = string
    last_name  = string
    email      = string
    password   = string
  }))
  default   = {}
  sensitive = true
}
