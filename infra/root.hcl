# Root Terragrunt config: every unit under live/<env>/ includes this file.
# It generates the provider and backend blocks so modules stay plain
# OpenTofu, and loads env.hcl so each environment differs only in inputs.

locals {
  env = read_terragrunt_config(find_in_parent_folders("env.hcl")).locals
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<-EOT
    provider "keycloak" {
      url       = "${local.env.keycloak_admin_url}"
      realm     = "master"
      client_id = "admin-cli"
      username  = "${get_env("KEYCLOAK_ADMIN_USER", "admin")}"
      password  = "${get_env("KEYCLOAK_ADMIN_PASSWORD", "admin")}"
    }
  EOT
}

# Local state: fine for a laptop demo. State holds client secrets and seed
# passwords, so infra/.state/ is gitignored. Production would use an
# encrypted remote backend (S3 + DynamoDB lock, or OpenTofu state encryption).
remote_state {
  backend = "local"
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    path = "${get_parent_terragrunt_dir()}/.state/${path_relative_to_include()}/terraform.tfstate"
  }
}

inputs = local.env
