locals {
  # Browser-facing confidential clients. claims-app exists only to prove SSO:
  # a second client that shares the Keycloak session with the portal.
  browser_clients = {
    "portal-bff" = {
      name             = "Policyholder portal (BFF)"
      base_url         = var.bff_base_url
      backchannel_base = var.bff_backchannel_base_url
    }
    "claims-app" = {
      name             = "Claims app (SSO demo)"
      base_url         = var.claims_app_base_url
      backchannel_base = var.claims_app_backchannel_base_url
    }
  }
}

resource "keycloak_openid_client" "browser" {
  for_each = local.browser_clients

  realm_id    = keycloak_realm.this.id
  client_id   = each.key
  name        = each.value.name
  access_type = "CONFIDENTIAL"

  # Authorization code + PKCE only.
  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  pkce_code_challenge_method   = "S256"

  # Exact URIs, no wildcards (open-redirect defence).
  valid_redirect_uris             = ["${each.value.base_url}/callback"]
  valid_post_logout_redirect_uris = ["${each.value.base_url}/"]
  web_origins                     = [each.value.base_url]
  root_url                        = each.value.base_url

  frontchannel_logout_enabled         = false
  backchannel_logout_url              = "${each.value.backchannel_base}/backchannel-logout"
  backchannel_logout_session_required = true
}

resource "keycloak_client_scope_assignments" "browser" {
  for_each = keycloak_openid_client.browser

  realm_id        = keycloak_realm.this.id
  client_id       = each.value.id
  default_scopes  = local.default_scopes
  optional_scopes = local.optional_scopes
}

# policy-api is only an audience: it receives tokens, it never obtains them.
# Keycloak 26 hides "bearer-only", so this is a confidential client with
# every flow switched off.
resource "keycloak_openid_client" "policy_api" {
  realm_id    = keycloak_realm.this.id
  client_id   = "policy-api"
  name        = "Policy API (resource server)"
  access_type = "CONFIDENTIAL"

  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
}

# Local-only client-credentials client, so S2 can curl a real Keycloak
# token into policy-api.
resource "keycloak_openid_client" "test" {
  count = var.enable_test_client ? 1 : 0

  realm_id    = keycloak_realm.this.id
  client_id   = "warden-test"
  name        = "Warden test client (local only)"
  access_type = "CONFIDENTIAL"

  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = true
}

resource "keycloak_client_scope_assignments" "test" {
  count = var.enable_test_client ? 1 : 0

  realm_id        = keycloak_realm.this.id
  client_id       = keycloak_openid_client.test[0].id
  default_scopes  = local.default_scopes
  optional_scopes = local.optional_scopes
}
