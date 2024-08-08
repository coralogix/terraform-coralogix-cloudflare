# Cloudflare Coralogix Terraform module

## Requirements

`Terraform` - Version 1.20+
`Cloudflare` - Version 4.0+

## Usage

`logpush-job`:

```hcl
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
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
    cloudflare_logpush_fields = ["EdgeStartTimestamp", "EdgePathingOp", "EdgePathingSrc"] # Need to include 'Timestamp' key, can be left empty aswell for all fields
    cloudflare_zone_id = "xxxxxxxxxxxxxxxxxxxxx" # to be used with zone-scoped datasets
    # cloudflare_account_id = "xxxxxxxxxxxxxxxx" # to be used with account-scoped datasets
}
```

By default, the integration will set application_name as Cloudflare, and subsystem_name as the data set name if values are not specified.

WARNING: Breaking Change in version 1.10 - New output_options added in cloudflare/cloudflare

## Authors

Module is maintained by [Coralogix](https://github.com/coralogix).

## License

Apache 2 Licensed. See [LICENSE](https://github.com/coralogix/terraform-coralogix-aws/tree/master/LICENSE) for full details.
