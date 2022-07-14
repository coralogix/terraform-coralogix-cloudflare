# Cloudflare Coralogix Terraform module

## Requirements

`Terraform` - Version 1.20+
`Cloudflare` - Version 3+

## Usage

`logpush-job`:

```hcl
module "logpush-job" {
    source = "coralogix/cloudflare/coralogix//modules/logpush-job"

    coralogix_region   = "Europe"
    coralogix_private_key = "79cf16dc-0dfa-430e-a651-ec76bfa96d01"
    cloudflare_email = "example@coralogix.com"
    cloudflare_api_key = "7ae12522bce3d8d988ec5f0ed8b8ef9016e09"
    cloudflare_logpush_dataset = "http_requests"
    cloudflare_logpush_fields = "RayID,ZoneName" # can be left empty aswell for all fields
    cloudflare_zone_id = "ca17eeeb371963f662965e4de0ed7403" # to be used with zone-scoped datasets
    # cloudflare_account_id = "bc20385621cb7dc622aeb4810ca235df" # to be used with account-scoped datasets
}
```

## Authors

Module is maintained by [Coralogix](https://github.com/coralogix).

## License

Apache 2 Licensed. See [LICENSE](https://github.com/coralogix/terraform-coralogix-aws/tree/master/LICENSE) for full details.