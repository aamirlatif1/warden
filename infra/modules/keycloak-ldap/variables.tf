variable "realm" {
  description = "Realm that federates the directory (insurance)."
  type        = string
}

variable "connection_url" {
  description = "LDAP URL as Keycloak reaches it, e.g. ldap://openldap:389. Production: ldaps:// with a pinned CA."
  type        = string
}

variable "bind_dn" {
  description = "Service account Keycloak binds as to search users."
  type        = string
}

variable "bind_credential" {
  description = "Password of bind_dn."
  type        = string
  sensitive   = true
}

variable "users_dn" {
  description = "Where underwriters live."
  type        = string
  default     = "ou=underwriters,dc=warden,dc=local"
}

variable "groups_dn" {
  description = "Where LDAP groups live."
  type        = string
  default     = "ou=groups,dc=warden,dc=local"
}

variable "ldap_group" {
  description = "LDAP group (cn) whose members are underwriters."
  type        = string
  default     = "underwriters"
}

variable "role" {
  description = "Realm role granted to members of ldap_group."
  type        = string
  default     = "underwriter"
}
