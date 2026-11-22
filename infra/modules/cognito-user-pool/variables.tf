variable "name" {
  description = "User pool name."
  type        = string
  default     = "warden-partners"
}

variable "region" {
  description = "AWS region, only used to build the issuer URL output."
  type        = string
  default     = "eu-central-1"
}

variable "domain_prefix" {
  description = "Hosted domain prefix: https://<prefix>.auth.<region>.amazoncognito.com."
  type        = string
  default     = "warden-partners-demo"
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "resource_server_identifier" {
  description = "Prefix of every scope; Cognito's stand-in for an audience."
  type        = string
  default     = "https://policy-api.warden.example"
}

variable "scopes" {
  description = "Custom scopes, name → description. Cognito scope names cannot contain ':'."
  type        = map(string)
  default = {
    "quotes.write" = "Create quotes for the partner's own tenant"
    "quotes.read"  = "Read the partner's own quotes"
  }
}

variable "partners" {
  description = "Partner app clients and the scopes each may request."
  type = map(object({
    scopes = list(string)
  }))
  default = {
    shopr = { scopes = ["quotes.write", "quotes.read"] }
  }

  validation {
    condition     = alltrue([for p in var.partners : length(p.scopes) > 0])
    error_message = "Every partner needs at least one scope."
  }
}
