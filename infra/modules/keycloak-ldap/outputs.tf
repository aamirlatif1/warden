output "federation_id" {
  description = "Keycloak component ID of the LDAP provider (for a manual sync: POST .../user-storage/<id>/sync?action=triggerFullSync)."
  value       = keycloak_ldap_user_federation.directory.id
}
