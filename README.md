# Cloudflare Coralogix Terraform module

## Requirements

`Terraform` - Version 1.20+
`Cloudflare` - Version 3+

## Usage

`logpush-job`:

```hcl
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 3.0"
    }
  }
}

provider "cloudflare" {
  email   = "example@coralogix.com"
  api_key = "XXXXXXXXXX"
}

module "logpush-job" {
    source = "coralogix/cloudflare/coralogix//modules/logpush-job"

    coralogix_region   = "Europe"
    coralogix_private_key = "XXXXXX-XXXXX"
    coralogix_application_name = "myapp_cloudflare"
    coralogix_subsystem_name = "mysub_cloudflare"
    cloudflare_logpush_dataset = "http_requests"
    cloudflare_logpush_fields = "RayID,ZoneName" # can be left empty aswell for all fields
    cloudflare_zone_id = "ca17eeeb371963f662965e4de0ed7403" # to be used with zone-scoped datasets
    # cloudflare_account_id = "bc20385621cb7dc622aeb4810ca235df" # to be used with account-scoped datasets
}
```

By default, the integration will set application_name as Cloudflare, and subsystem_name as the data set name if values are not specified.

## Authors

Module is maintained by [Coralogix](https://github.com/coralogix).

## License

Apache 2 Licensed. See [LICENSE](https://github.com/coralogix/terraform-coralogix-aws/tree/master/LICENSE) for full details.
