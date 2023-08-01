terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  email   = "juan@coralogix.com"
  api_key = "18367bed44bda3fca5d4c8da1277174f8334f"
}

module "logpush-job" {
    source = "../modules/logpush-job"
    #coralogix_application_name = "terraform"
    #coralogix_subsystem_name = "cloudflare" 
    coralogix_region   = "Europe"
    coralogix_private_key = "be1fe366-ed73-a842-bb3e-74fa24c1c3fe"
    #cloudflare_logpush_dataset = "http_requests"
    cloudflare_logpush_dataset = "audit_logs"
    #cloudflare_logpush_fields = "RayID,ZoneName" # can be left empty aswell for all fields
    cloudflare_logpush_fields = "ID,ActionType,ActionResult" # can be left empty aswell for all fields
    #cloudflare_zone_id = "e42d5372648c1e877835b0c4af7f81c4" # to be used with zone-scoped datasets
    cloudflare_account_id = "178368581027f2ab845898d7ad9e1561" # to be used with account-scoped datasets
}
