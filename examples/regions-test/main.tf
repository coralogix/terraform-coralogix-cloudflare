# Plan-only fixture that instantiates the logpush-job module once per region to
# validate that the region map, coralogix_endpoint local, and variable validation
# all plan correctly across the supported regions (including US3 and Custom).

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.38"
    }
  }
}

provider "cloudflare" {
  # Credentials are not needed for `terraform plan`; the provider is configured
  # only so the module's required_providers constraint is satisfied.
  api_token = "plan-only-placeholder"
}

locals {
  regions = ["EU1", "EU2", "US1", "US2", "US3", "AP1", "AP2", "AP3"]
}

module "logpush_job" {
  source   = "../../modules/logpush-job"
  for_each = toset(local.regions)

  coralogix_region           = each.value
  coralogix_private_key      = "placeholder-private-key"
  coralogix_application_name = "regions-test-app"
  coralogix_subsystem_name   = "regions-test-sub"
  cloudflare_logpush_dataset = "http_requests"
  cloudflare_zone_id         = "00000000000000000000000000000000"
}

# Exercise the Custom region / custom_domain code path as well.
module "logpush_job_custom" {
  source = "../../modules/logpush-job"

  coralogix_region           = "Custom"
  custom_domain              = "private.us1.coralogix.com"
  coralogix_private_key      = "placeholder-private-key"
  coralogix_application_name = "regions-test-app"
  coralogix_subsystem_name   = "regions-test-sub"
  cloudflare_logpush_dataset = "audit_logs"
  cloudflare_account_id      = "00000000000000000000000000000000"
}
