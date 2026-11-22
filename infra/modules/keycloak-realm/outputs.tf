output "realm" {
  value = keycloak_realm.this.realm
}

output "issuer" {
  description = "Value of the iss claim in this realm's tokens."
  value       = "${var.keycloak_public_url}/realms/${keycloak_realm.this.realm}"
}

output "client_secrets" {
  description = "Secrets of the confidential clients that obtain tokens."
  sensitive   = true
  value = merge(
    { for k, c in keycloak_openid_client.browser : k => c.client_secret },
    var.enable_test_client ? { "warden-test" = keycloak_openid_client.test[0].client_secret } : {},
  )
}
