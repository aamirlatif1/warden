# In realm "insurance": Nordbank as a SAML identity provider (identity
# brokering). A bank customer clicks "Log in with Nordbank", authenticates
# at the bank, and Keycloak creates (first broker login) or links an
# insurance account. The access token then carries partner_id=nordbank.

resource "keycloak_saml_identity_provider" "nordbank" {
  realm        = var.realm
  alias        = var.alias
  display_name = "Nordbank"
  enabled      = true

  entity_id                  = local.sp_entity_id # our SP entity ID
  single_sign_on_service_url = local.idp_sso_url
  post_binding_authn_request = true
  post_binding_response      = true
  backchannel_supported      = false

  # Only signed assertions, verified with the bank's certificate.
  validate_signature     = true
  want_assertions_signed = true
  signing_certificate    = data.keycloak_realm_keys.nordbank.keys[0].certificate
  signature_algorithm    = "RSA_SHA256"

  name_id_policy_format = "Persistent"
  principal_type        = "SUBJECT"

  # Re-apply mapped attributes on every login, so the bank stays the source
  # of truth for name and email, and partner_id can't drift.
  sync_mode   = "FORCE"
  trust_email = true
  store_token = false

  first_broker_login_flow_alias = "first broker login"

  extra_config = {
    # Reject assertions whose Issuer is not the bank's entity ID.
    idpEntityId = local.idp_entity
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "attr" {
  for_each = {
    email     = "email"
    firstName = "firstName"
    lastName  = "lastName"
  }

  realm                   = var.realm
  identity_provider_alias = keycloak_saml_identity_provider.nordbank.alias
  name                    = "import-${each.key}"
  attribute_name          = each.key
  user_attribute          = each.value
  extra_config            = { syncMode = "INHERIT" }
}

# Tenant: every account that comes through this broker belongs to Nordbank.
# Hard-coded by the broker, never taken from the assertion, so the bank
# can't claim another partner's tenant.
resource "keycloak_hardcoded_attribute_identity_provider_mapper" "partner_id" {
  realm                   = var.realm
  identity_provider_alias = keycloak_saml_identity_provider.nordbank.alias
  name                    = "partner-id"
  attribute_name          = "partner_id"
  attribute_value         = var.partner_id
  user_session            = false
  extra_config            = { syncMode = "INHERIT" }
}

resource "keycloak_hardcoded_role_identity_provider_mapper" "policyholder" {
  realm                   = var.realm
  identity_provider_alias = keycloak_saml_identity_provider.nordbank.alias
  name                    = "role-policyholder"
  role                    = "policyholder"
  extra_config            = { syncMode = "INHERIT" }
}

# Readable local username ("nordbank.nora@nordbank.example") instead of
# the opaque persistent NameID. The NameID stays the stable link between
# the two accounts; the username is display only.
resource "keycloak_user_template_importer_identity_provider_mapper" "username" {
  realm                   = var.realm
  identity_provider_alias = keycloak_saml_identity_provider.nordbank.alias
  name                    = "username"
  template                = "$${ALIAS}.$${ATTRIBUTE.email}"
  extra_config            = { syncMode = "INHERIT" }
}
