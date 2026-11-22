output "realm" {
  value = keycloak_realm.this.realm
}

output "issuer" {
  description = "Value of the iss claim in this realm's tokens."
  value       = "${var.keycloak_public_url}/realms/${keycloak_realm.this.realm}"
}

output "client_secrets" {
  description = "Secrets of the confidential clients (token clients, and policy-api for introspection)."
  sensitive   = true
  value = merge(
    { for k, c in keycloak_openid_client.browser : k => c.client_secret },
    # policy-api's own secret: it introspects high-risk tokens (RFC 7662).
    { "policy-api" = keycloak_openid_client.policy_api.client_secret },
    var.enable_test_client ? { "warden-test" = keycloak_openid_client.test[0].client_secret } : {},
  )
}

output "user_ids" {
  description = "Keycloak user ID (the sub claim) of each seed user. policy-seed uses these as policy owners."
  value       = { for name, u in keycloak_user.seed : name => u.id }
}
