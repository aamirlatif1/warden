# LDAP user federation for the underwriter actor (REQUIREMENTS FR-1). The
# insurer's directory (OpenLDAP standing in for Active Directory) stays the
# source of truth: Keycloak imports users on first login, read-only, and
# verifies passwords against LDAP with a bind.

data "keycloak_realm" "this" {
  realm = var.realm
}

resource "keycloak_ldap_user_federation" "directory" {
  realm_id = data.keycloak_realm.this.id
  name     = "warden-directory"
  enabled  = true
  vendor   = "OTHER" # "AD" for Active Directory: different default mappers

  connection_url  = var.connection_url
  bind_dn         = var.bind_dn
  bind_credential = var.bind_credential
  users_dn        = var.users_dn
  search_scope    = "ONE_LEVEL"

  username_ldap_attribute = "uid"
  rdn_ldap_attribute      = "uid"
  uuid_ldap_attribute     = "entryUUID"
  user_object_classes     = ["inetOrgPerson"]

  # Keycloak never writes to the directory; HR owns it.
  edit_mode          = "READ_ONLY"
  import_enabled     = true
  sync_registrations = false
  trust_email        = true
  pagination         = true

  # Users are imported on demand at first login; no periodic sync for a
  # laptop demo. Production: changed-users sync every few minutes, so a
  # leaver disabled in AD is disabled here too.
  full_sync_period    = -1
  changed_sync_period = -1
}

# LDAP group → Keycloak group "underwriters" → realm role "underwriter".
# The names differ on purpose: the directory's naming is HR's, the role is
# the application's.
resource "keycloak_group" "underwriters" {
  realm_id = data.keycloak_realm.this.id
  name     = var.ldap_group
}

data "keycloak_role" "underwriter" {
  realm_id = data.keycloak_realm.this.id
  name     = var.role
}

resource "keycloak_group_roles" "underwriters" {
  realm_id = data.keycloak_realm.this.id
  group_id = keycloak_group.underwriters.id
  role_ids = [data.keycloak_role.underwriter.id]
}

resource "keycloak_ldap_group_mapper" "groups" {
  realm_id                = data.keycloak_realm.this.id
  ldap_user_federation_id = keycloak_ldap_user_federation.directory.id
  name                    = "ldap-groups"

  ldap_groups_dn                 = var.groups_dn
  group_name_ldap_attribute      = "cn"
  group_object_classes           = ["groupOfNames"]
  membership_ldap_attribute      = "member"
  membership_attribute_type      = "DN"
  membership_user_ldap_attribute = "uid"
  memberof_ldap_attribute        = "memberOf"
  user_roles_retrieve_strategy   = "LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"
  mode                           = "READ_ONLY"
  preserve_group_inheritance     = false

  drop_non_existing_groups_during_sync = false

  # The group must exist (with its role) before the mapper links to it.
  depends_on = [keycloak_group_roles.underwriters]
}
