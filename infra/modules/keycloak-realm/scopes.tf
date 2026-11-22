# Client scope "policies": every token that carries it is meant for
# policy-api. The audience mapper puts aud=policy-api in the access token,
# which policy-api's validator requires.
resource "keycloak_openid_client_scope" "policies" {
  realm_id               = keycloak_realm.this.id
  name                   = "policies"
  description            = "Access to policy-api"
  include_in_token_scope = true
}

resource "keycloak_openid_audience_protocol_mapper" "policy_api" {
  realm_id                 = keycloak_realm.this.id
  client_scope_id          = keycloak_openid_client_scope.policies.id
  name                     = "audience-policy-api"
  included_client_audience = keycloak_openid_client.policy_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_user_attribute_protocol_mapper" "partner_id" {
  realm_id            = keycloak_realm.this.id
  client_scope_id     = keycloak_openid_client_scope.policies.id
  name                = "partner_id"
  user_attribute      = "partner_id"
  claim_name          = "partner_id"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}

resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id            = keycloak_realm.this.id
  client_scope_id     = keycloak_openid_client_scope.policies.id
  name                = "groups"
  claim_name          = "groups"
  full_path           = false
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}

locals {
  # Keycloak 26's built-in default scopes, plus ours. The assignment
  # resource replaces the whole list, so the built-ins must be repeated.
  default_scopes = ["acr", "basic", "email", "profile", "roles", "web-origins", keycloak_openid_client_scope.policies.name]

  # No optional scopes. This drops Keycloak's defaults, including
  # offline_access: no client here may hold offline (non-expiring) tokens.
  optional_scopes = []
}
