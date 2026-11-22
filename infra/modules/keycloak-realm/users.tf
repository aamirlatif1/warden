# Synthetic seed users (dev only; passwords come from the environment's
# inputs and live in local state, which is gitignored).
resource "keycloak_user" "seed" {
  for_each = nonsensitive(toset(keys(var.seed_users)))

  realm_id       = keycloak_realm.this.id
  username       = each.key
  enabled        = true
  email          = var.seed_users[each.key].email
  email_verified = true
  first_name     = var.seed_users[each.key].first_name
  last_name      = var.seed_users[each.key].last_name

  attributes = var.seed_users[each.key].partner_id == "" ? {} : {
    partner_id = var.seed_users[each.key].partner_id
  }

  initial_password {
    value     = var.seed_users[each.key].password
    temporary = false
  }

  # partner_id must be declared in the user profile before it can be stored.
  depends_on = [keycloak_realm_user_profile.this]
}

resource "keycloak_user_roles" "seed" {
  for_each = keycloak_user.seed

  realm_id   = keycloak_realm.this.id
  user_id    = each.value.id
  exhaustive = false
  role_ids   = [for r in nonsensitive(var.seed_users[each.key].roles) : keycloak_role.realm[r].id]
}
