output "issuer" {
  description = "Value of iss in Cognito access tokens (match exactly in the issuer profile)."
  value       = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}

output "jwks_uri" {
  value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}/.well-known/jwks.json"
}

output "token_endpoint" {
  value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.region}.amazoncognito.com/oauth2/token"
}

output "client_ids" {
  description = "Partner → app client ID: the allow-list for the client_id claim (Cognito has no aud in access tokens)."
  value       = { for k, c in aws_cognito_user_pool_client.partner : k => c.id }
}
