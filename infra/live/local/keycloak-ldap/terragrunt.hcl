include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "${get_parent_terragrunt_dir("root")}/modules/keycloak-ldap"
}

# The realm (and its underwriter role) must exist first.
dependency "realm" {
  config_path = "../keycloak-realm"

  mock_outputs                            = { realm = "insurance" }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  realm = dependency.realm.outputs.realm
}
