output "bank_realm" {
  value = keycloak_realm.nordbank.realm
}

output "idp_alias" {
  description = "Send as kc_idp_hint to skip the insurer's login page."
  value       = keycloak_saml_identity_provider.nordbank.alias
}
