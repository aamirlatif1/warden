# Inputs for the local laptop environment (deploy/compose.yaml).
locals {
  environment = "local"

  # Where the tools container reaches Keycloak's admin API (compose network).
  keycloak_admin_url = "http://keycloak:8080"

  # Base URL in the iss claim (KC_HOSTNAME in compose).
  keycloak_public_url = "http://localhost:8080"

  # Browser-facing base URLs of the Go services (run on the host).
  bff_base_url        = "http://localhost:8082"
  claims_app_base_url = "http://localhost:8084"

  # Keycloak (in Docker) calls the BFF's back-channel logout endpoint.
  bff_backchannel_base_url        = "http://host.docker.internal:8082"
  claims_app_backchannel_base_url = "http://host.docker.internal:8084"

  access_token_lifespan    = "5m"
  sso_session_idle_timeout = "30m"
  sso_session_max_lifespan = "10h"

  # Client-credentials client for curl tests. Never enabled outside local.
  enable_test_client = true

  # LDAP federation (keycloak-ldap): Keycloak, in Docker, reaches OpenLDAP
  # by its compose service name. Dev-only admin bind from compose.yaml.
  connection_url  = "ldap://openldap:389"
  bind_dn         = "cn=admin,dc=warden,dc=local"
  bind_credential = "admin"

  # Simulated bank customers in realm nordbank (keycloak-broker), dev only.
  bank_users = {
    nora = { first_name = "Nora", last_name = "Bankcustomer", email = "nora@nordbank.example", password = "nora-dev-password" }
  }

  # Synthetic seed users, dev only.
  seed_users = {
    anna = { first_name = "Anna", last_name = "Policyholder", email = "anna@example.test", password = "anna-dev-password", roles = ["policyholder"], partner_id = "" }
    bob  = { first_name = "Bob", last_name = "Policyholder", email = "bob@example.test", password = "bob-dev-password1", roles = ["policyholder"], partner_id = "" }
  }
}
