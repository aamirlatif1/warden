# tofu test with a mocked AWS provider: no credentials, no API calls.
# Checks the plan, not AWS behaviour.

mock_provider "aws" {
  mock_resource "aws_cognito_user_pool" {
    defaults = { id = "eu-central-1_Mock123" }
  }
}

run "partner_client_is_client_credentials_only" {
  command = plan

  assert {
    condition     = aws_cognito_user_pool_client.partner["shopr"].allowed_oauth_flows == toset(["client_credentials"])
    error_message = "partner clients must only use client_credentials"
  }

  assert {
    condition     = aws_cognito_user_pool_client.partner["shopr"].generate_secret == true
    error_message = "client credentials need a secret in Cognito"
  }

  assert {
    condition     = aws_cognito_user_pool_client.partner["shopr"].access_token_validity == 5
    error_message = "access tokens should live 5 minutes, like partner-sts"
  }

  assert {
    condition     = aws_cognito_user_pool.this.mfa_configuration == "ON"
    error_message = "MFA must be on for human users"
  }
}

run "scopes_are_prefixed_with_the_resource_server" {
  command = apply # mocked: computes ids from the mock defaults

  assert {
    condition     = contains(aws_cognito_user_pool_client.partner["shopr"].allowed_oauth_scopes, "https://policy-api.warden.example/quotes.write")
    error_message = "scopes must be <identifier>/<scope>"
  }

  assert {
    condition     = output.issuer == "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Mock123"
    error_message = "issuer must be the pool URL (exact iss match in the validator)"
  }
}

run "partner_without_scopes_is_rejected" {
  command = plan

  variables {
    partners = { empty = { scopes = [] } }
  }

  expect_failures = [var.partners]
}
