# Browser flow "browser-mfa" (REQUIREMENTS FR-1):
#
#   Cookie                                  ALTERNATIVE  (SSO: existing session)
#   Identity Provider Redirector            ALTERNATIVE  (kc_idp_hint=nordbank)
#   forms                                   ALTERNATIVE
#     level 1 (silver)                      CONDITIONAL  loa=1, max age 10 h
#       Username Password Form              REQUIRED
#       underwriter OTP                     CONDITIONAL
#         Condition - user role underwriter REQUIRED
#         OTP Form                          REQUIRED     (conditional MFA by role)
#     level 2 (gold)                        CONDITIONAL  loa=2, max age 5 min
#       second factor                       REQUIRED
#         webauthn                          CONDITIONAL
#           Condition - user configured     REQUIRED     (has a security key)
#           WebAuthn Authenticator          REQUIRED
#         otp                               CONDITIONAL
#           Condition - sub-flow executed   REQUIRED     (webauthn did not run)
#           OTP Form                        REQUIRED     (enrols TOTP if absent)
#
# Level 2 is "WebAuthn if registered, else OTP". Two ALTERNATIVE executions
# would be shorter, but Keycloak fails the login when the user has neither
# credential instead of offering enrolment (found applying S7).
#
# A client asks for level 2 with acr_values=gold (step-up); the realm's
# acr.loa.map turns "gold" into 2 and level 2 back into acr=gold in tokens.
# Level 2's max age (300 s) matches policy-api's auth_time rule, so an old
# gold login is asked for its second factor again.

resource "keycloak_authentication_flow" "browser_mfa" {
  realm_id    = keycloak_realm.this.id
  alias       = "browser-mfa"
  description = "Browser login with conditional OTP for underwriters and LoA step-up (silver=1, gold=2)"
}

resource "keycloak_authentication_execution" "cookie" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_flow.browser_mfa.alias
  authenticator     = "auth-cookie"
  requirement       = "ALTERNATIVE"
  priority          = 10
}

resource "keycloak_authentication_execution" "idp_redirector" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_flow.browser_mfa.alias
  authenticator     = "identity-provider-redirector"
  requirement       = "ALTERNATIVE"
  priority          = 20
}

resource "keycloak_authentication_subflow" "forms" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_flow.browser_mfa.alias
  alias             = "browser-mfa forms"
  provider_id       = "basic-flow"
  requirement       = "ALTERNATIVE"
  priority          = 30
}

# ---- level 1: password (+ OTP for underwriters) ----

resource "keycloak_authentication_subflow" "level1" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.forms.alias
  alias             = "browser-mfa level 1"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 10
}

resource "keycloak_authentication_execution" "level1_condition" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.level1.alias
  authenticator     = "conditional-level-of-authentication"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "level1_condition" {
  realm_id     = keycloak_realm.this.id
  execution_id = keycloak_authentication_execution.level1_condition.id
  alias        = "loa-level-1"
  config = {
    "loa-condition-level" = "1"
    "loa-max-age"         = "36000"
  }
}

resource "keycloak_authentication_execution" "password" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.level1.alias
  authenticator     = "auth-username-password-form"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_authentication_subflow" "underwriter_otp" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.level1.alias
  alias             = "browser-mfa underwriter otp"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 30
}

resource "keycloak_authentication_execution" "underwriter_condition" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.underwriter_otp.alias
  authenticator     = "conditional-user-role"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "underwriter_condition" {
  realm_id     = keycloak_realm.this.id
  execution_id = keycloak_authentication_execution.underwriter_condition.id
  alias        = "role-underwriter"
  config = {
    condUserRole = keycloak_role.realm["underwriter"].name
    negate       = "false"
  }
}

resource "keycloak_authentication_execution" "underwriter_otp" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.underwriter_otp.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"
  priority          = 20
}

# ---- level 2: second factor (step-up) ----

resource "keycloak_authentication_subflow" "level2" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.forms.alias
  alias             = "browser-mfa level 2"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 20
}

resource "keycloak_authentication_execution" "level2_condition" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.level2.alias
  authenticator     = "conditional-level-of-authentication"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "level2_condition" {
  realm_id     = keycloak_realm.this.id
  execution_id = keycloak_authentication_execution.level2_condition.id
  alias        = "loa-level-2"
  config = {
    "loa-condition-level" = "2"
    "loa-max-age"         = "300"
  }
}

resource "keycloak_authentication_subflow" "second_factor" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.level2.alias
  alias             = "browser-mfa second factor"
  provider_id       = "basic-flow"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_authentication_subflow" "stepup_webauthn" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.second_factor.alias
  alias             = "browser-mfa webauthn"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 10
}

resource "keycloak_authentication_execution" "stepup_webauthn_configured" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.stepup_webauthn.alias
  authenticator     = "conditional-user-configured"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution" "stepup_webauthn" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.stepup_webauthn.alias
  authenticator     = "webauthn-authenticator"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_authentication_subflow" "stepup_otp" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.second_factor.alias
  alias             = "browser-mfa otp"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 20
}

resource "keycloak_authentication_execution" "stepup_otp_condition" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.stepup_otp.alias
  authenticator     = "conditional-sub-flow-executed"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "stepup_otp_condition" {
  realm_id     = keycloak_realm.this.id
  execution_id = keycloak_authentication_execution.stepup_otp_condition.id
  alias        = "webauthn-not-executed"
  config = {
    flow_to_check = keycloak_authentication_subflow.stepup_webauthn.alias
    check_result  = "not-executed"
  }
}

resource "keycloak_authentication_execution" "stepup_otp" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_subflow.stepup_otp.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_authentication_bindings" "this" {
  realm_id     = keycloak_realm.this.id
  browser_flow = keycloak_authentication_flow.browser_mfa.alias

  # Bind only once the whole tree exists: a half-built browser flow would
  # lock everyone out.
  depends_on = [
    keycloak_authentication_execution.cookie,
    keycloak_authentication_execution.idp_redirector,
    keycloak_authentication_execution_config.level1_condition,
    keycloak_authentication_execution.password,
    keycloak_authentication_execution_config.underwriter_condition,
    keycloak_authentication_execution.underwriter_otp,
    keycloak_authentication_execution_config.level2_condition,
    keycloak_authentication_execution.stepup_webauthn_configured,
    keycloak_authentication_execution.stepup_webauthn,
    keycloak_authentication_execution_config.stepup_otp_condition,
    keycloak_authentication_execution.stepup_otp,
  ]
}
