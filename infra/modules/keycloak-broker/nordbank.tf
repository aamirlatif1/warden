# Realm "nordbank" plays the partner bank's own identity provider. It speaks
# SAML 2.0 to the insurer, as a bank's IdP typically would. In production
# this realm would not exist: the bank runs its IdP and sends its metadata.

resource "keycloak_realm" "nordbank" {
  realm        = var.bank_realm
  enabled      = true
  display_name = "Nordbank (simulated partner bank)"

  ssl_required                = "external"
  login_with_email_allowed    = true
  default_signature_algorithm = "RS256"

  security_defenses {
    brute_force_detection {
      permanent_lockout      = false
      max_login_failures     = 5
      wait_increment_seconds = 60
    }
  }
}

# Synthetic bank customers (dev only).
resource "keycloak_user" "customer" {
  for_each = nonsensitive(toset(keys(var.bank_users)))

  realm_id       = keycloak_realm.nordbank.id
  username       = each.key
  enabled        = true
  email          = var.bank_users[each.key].email
  email_verified = true
  first_name     = var.bank_users[each.key].first_name
  last_name      = var.bank_users[each.key].last_name

  initial_password {
    value     = var.bank_users[each.key].password
    temporary = false
  }
}

locals {
  issuer_base = "${var.keycloak_public_url}/realms"
  # The insurer's realm is the SAML service provider; its entity ID is the
  # realm URL, and assertions are posted to the broker endpoint.
  sp_entity_id = "${local.issuer_base}/${var.realm}"
  acs_url      = "${local.issuer_base}/${var.realm}/broker/${var.alias}/endpoint"
  idp_entity   = "${local.issuer_base}/${keycloak_realm.nordbank.realm}"
  idp_sso_url  = "${local.issuer_base}/${keycloak_realm.nordbank.realm}/protocol/saml"
}

# The insurer, registered at the bank as a SAML SP.
resource "keycloak_saml_client" "insurer" {
  realm_id  = keycloak_realm.nordbank.id
  client_id = local.sp_entity_id
  name      = "Warden Insurance (SAML service provider)"

  # Sign the response and the assertion (XML signature wrapping defence
  # lives on the SP side: it must validate the signed assertion it reads).
  sign_documents          = true
  sign_assertions         = true
  signature_algorithm     = "RSA_SHA256"
  include_authn_statement = true
  encrypt_assertions      = false

  # AuthnRequests are not signed by the SP here (fewer keys to wire for a
  # laptop demo). Exact ACS URL matching still stops responses going
  # anywhere else. Production: sign requests, rotate certs via metadata.
  client_signature_required = false

  force_post_binding          = true
  front_channel_logout        = false
  name_id_format              = "persistent"
  force_name_id_format        = true
  full_scope_allowed          = false
  valid_redirect_uris         = [local.acs_url]
  assertion_consumer_post_url = local.acs_url
}

# Attributes the insurer needs to create the account at first login.
resource "keycloak_saml_user_property_protocol_mapper" "attr" {
  for_each = {
    email     = "email"
    firstName = "firstName"
    lastName  = "lastName"
  }

  realm_id                   = keycloak_realm.nordbank.id
  client_id                  = keycloak_saml_client.insurer.id
  name                       = each.key
  user_property              = each.value
  saml_attribute_name        = each.key
  saml_attribute_name_format = "Basic"
}

# The bank realm's active RS256 certificate: what the insurer trusts to
# verify assertions. Read from Keycloak, so a fresh stack needs no copying.
data "keycloak_realm_keys" "nordbank" {
  realm_id   = keycloak_realm.nordbank.id
  algorithms = ["RS256"]
  status     = ["ACTIVE"]
}
