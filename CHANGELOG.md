# Changelog
## v1.2.0 / 2025-01-03
### 💥 Breaking Change 💥 
- Removed max_upload_bytes and max_upload_records to match Coralogix Ingress
## v1.1.0 / 2024-12-15
### 💡 Enhancements 💡
- Add support for new region `AP3`, and for  regions syntax: `EU1`, `EU2`, `AP1`, `AP2`, `US1`
- Replaced deprecated filed `frequency` with `max_upload_bytes`, `max_upload_interval_seconds` and  `max_upload_records` 
- Add default value for `coralogix_application_name` and `coralogix_subsystem_name` variables: `cx-Cloudflare-Logpush-default-application`, `cx-Cloudflare-Logpush-default-subsystem`

## v1.0.12 / 2024-08-12
### 💡 Enhancements 💡
- page_shield_events and sinkhole_http_logs Datasets added.

## v1.0.11 / 2024-08-08
### 💥 Breaking Change 💥 
- Upstream update from logpush_options to output_options.