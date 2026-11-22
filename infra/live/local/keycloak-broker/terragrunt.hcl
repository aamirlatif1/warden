include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "${get_parent_terragrunt_dir("root")}/modules/keycloak-broker"
}

# The broker is added to the insurer's realm, so that realm comes first.
dependency "realm" {
  config_path = "../keycloak-realm"

  mock_outputs                            = { realm = "insurance" }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  realm = dependency.realm.outputs.realm
}
