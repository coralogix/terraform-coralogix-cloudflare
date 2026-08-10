# Changelog

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
