# Changelog

## v1.5.0
### 💡 Enhancements 💡
- Added support for the `US3` region (`ingress.us3.coralogix.com`) and a new `Custom` region that, combined with the new `custom_domain` variable, lets you point the logpush job at a private / self-hosted Coralogix ingress endpoint.
- Introduced the `local.coralogix_endpoint` value which resolves either a known region or `ingress.${custom_domain}` for `Custom`, and is now used to build all `destination_conf` URLs.
- Added a plan-only example fixture under `examples/regions-test` that instantiates the module across every supported region (plus `Custom`) to guard the region map and validation.
- Set `required_version = ">= 1.3.0"` in the module's `versions.tf`.

### 🧰 Bug fixes 🧰
- Fixed the `coralogix_region` validation: it previously accepted `Ap2`/duplicate `US2` while omitting `AP2` and `US1`, so valid regions were rejected and the error message did not match the accepted list. The accepted set is now `[EU1, EU2, US1, US2, US3, AP1, AP2, AP3, Custom]` plus the legacy names `[Europe, Europe2, India, Singapore, US, Indonesia]`.
- Fixed an account-scope path bug in `cloudflare_logpush_job.crx-logpush-account`: when both application and subsystem names were empty the fallback built `/api/v1/cloudflare/logs`, which the ingress rejected. It now builds `/cloudflare/v1/logs`, matching the other branches.


## v1.4.1
### 🧰 Bug fixes 🧰
- Corrected the documented timestamp key for two datasets added in v1.4.0. `websocket_analytics` now uses `EdgeEndTimestamp` and `email_security_post_delivery_events` now uses `CompletedAt`. Both records are emitted after the event they describe begins — a WebSocket at connection close, a post-delivery action on completion — so the previous keys (`EdgeStartTimestamp`, `MessageTimestamp`) could date a record more than 24h in the past and have it dropped at ingestion.

## v1.4.0
### 💡 Enhancements 💡
- Added the 15 Cloudflare Logpush datasets that were missing, bringing the module to Cloudflare's full catalog of 35: `websocket_analytics`, `zaraz_events` (zone) and `biso_user_actions`, `dex_application_tests`, `dex_device_state_events`, `dlp_forensic_copies`, `email_security_alerts`, `email_security_post_delivery_events`, `ipsec_logs`, `mcp_portal_logs`, `mnm_flow_logs`, `ssh_logs`, `turnstile_events`, `warp_config_changes`, `warp_toggle_changes` (account).

### 🧰 Bug fixes 🧰
- Fixed the Coralogix `header_dataset` value for `dns_firewall_logs` and `magic_ids_detections`, which were sent as `DnsFirewallLogs` and `MagicIdsDetections`. The ingress endpoint matches this header case-sensitively, so jobs created for either dataset were rejected with HTTP 400. They are now `DNSFirewallLogs` and `MagicIDSDetections`.
- The `cloudflare_logpush_dataset` validation error message omitted `page_shield_events` and `sinkhole_http_logs`, which the condition accepted. Both lists are now complete and identical.

## v1.3.0 / 2025-09-22
### 💡 Enhancements 💡
- Update ingress endpoints

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
