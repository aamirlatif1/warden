resource "keycloak_realm" "this" {
  realm        = var.realm_name
  enabled      = true
  display_name = "Warden Insurance"

  ssl_required                = "external"
  login_with_email_allowed    = true
  duplicate_emails_allowed    = false
  reset_password_allowed      = true
  default_signature_algorithm = "RS256"

  access_token_lifespan    = var.access_token_lifespan
  sso_session_idle_timeout = var.sso_session_idle_timeout
  sso_session_max_lifespan = var.sso_session_max_lifespan

  # Refresh-token rotation: each refresh token is single use. Presenting an
  # already-used one fails, and Keycloak ends the session (reuse detection).
  revoke_refresh_token    = true
  refresh_token_max_reuse = 0

  password_policy = "length(12) and notUsername and passwordHistory(3)"

  security_defenses {
    brute_force_detection {
      permanent_lockout                = false
      max_login_failures               = 5
      wait_increment_seconds           = 60
      quick_login_check_milli_seconds  = 1000
      minimum_quick_login_wait_seconds = 60
      max_failure_wait_seconds         = 900
      failure_reset_time_seconds       = 43200
    }
  }
}

resource "keycloak_role" "realm" {
  for_each = toset(["policyholder", "underwriter", "partner-agent"])

  realm_id = keycloak_realm.this.id
  name     = each.key
}
