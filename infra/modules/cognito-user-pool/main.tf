# AWS Cognito equivalent of the partner M2M setup, for comparison only
# (REQUIREMENTS FR-1). Never applied: validated and planned with a mocked
# provider (tests/plan.tftest.hcl). policy-api's Cognito issuer profile
# shows what would change on the resource server side:
#
#   - Access tokens carry client_id, NOT aud: the validator checks client_id
#     against an allow-list and requires token_use = "access".
#   - Scopes are "<resource-server-identifier>/<scope>", e.g.
#     "https://policy-api.warden.example/quotes.write".
#   - iss = https://cognito-idp.<region>.amazonaws.com/<pool-id>; JWKS at
#     <iss>/.well-known/jwks.json, RS256.
#   - Client credentials need a client secret (client_secret_basic); there
#     is no private_key_jwt, which is one reason Warden runs its own STS.

resource "aws_cognito_user_pool" "this" {
  name = var.name

  deletion_protection      = var.deletion_protection ? "ACTIVE" : "INACTIVE"
  mfa_configuration        = "ON"
  auto_verified_attributes = ["email"]

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = false
    temporary_password_validity_days = 3
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
}

# The hosted domain serves /oauth2/token for client credentials.
resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.domain_prefix
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_resource_server" "policy_api" {
  user_pool_id = aws_cognito_user_pool.this.id
  identifier   = var.resource_server_identifier
  name         = "policy-api"

  dynamic "scope" {
    for_each = var.scopes
    content {
      scope_name        = scope.key
      scope_description = scope.value
    }
  }
}

# One app client per partner, client credentials only.
resource "aws_cognito_user_pool_client" "partner" {
  for_each = var.partners

  name         = each.key
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = [for s in each.value.scopes : "${aws_cognito_resource_server.policy_api.identifier}/${s}"]
  supported_identity_providers         = ["COGNITO"]

  access_token_validity = 5
  token_validity_units {
    access_token = "minutes"
  }

  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true
}
