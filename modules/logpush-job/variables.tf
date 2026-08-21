variable "coralogix_region" {
  description = "The Coralogix region: [EU1, EU2, US1, US2, US3, AP1, AP2, AP3, Custom]. Legacy names [Europe, Europe2, India, Singapore, US, Indonesia] remain supported."
  type        = string
  default     = "EU1"
  validation {
    condition = contains([
      "EU1", "EU2", "US1", "US2", "US3", "AP1", "AP2", "AP3", "Custom",
      "Europe", "Europe2", "India", "Singapore", "US", "Indonesia"
    ], var.coralogix_region)
    error_message = "coralogix_region must be one of [EU1, EU2, US1, US2, US3, AP1, AP2, AP3, Custom], or a legacy name [Europe, Europe2, India, Singapore, US, Indonesia]."
  }
}

variable "coralogix_private_key" {
  description = "The Coralogix private key which is used to validate your authenticity"
  type        = string
  sensitive   = true
}

variable "cloudflare_logpush_dataset" {
  description = "The cloudflare logpush job data-set"
  type        = string
  # NOTE: this list, the error_message list, and the four maps in main.tf must be kept in
  # sync. Terraform cannot reference a local from a validation block, so it is repeated.
  validation {
    condition     = contains(["dns_logs", "firewall_events", "http_requests", "nel_reports", "spectrum_events", "page_shield_events", "audit_logs", "audit_logs_v2", "gateway_dns", "gateway_http", "gateway_network", "network_analytics_logs", "access_requests", "casb_findings", "device_posture_results", "dns_firewall_logs", "magic_ids_detections", "workers_trace_events", "sinkhole_http_logs", "zero_trust_network_sessions", "websocket_analytics", "zaraz_events", "biso_user_actions", "dex_application_tests", "dex_device_state_events", "dlp_forensic_copies", "email_security_alerts", "email_security_post_delivery_events", "ipsec_logs", "mcp_portal_logs", "mnm_flow_logs", "ssh_logs", "turnstile_events", "warp_config_changes", "warp_toggle_changes"], var.cloudflare_logpush_dataset)
    error_message = "Logpush dataset must be one of these values: ['dns_logs','firewall_events','http_requests','nel_reports','spectrum_events','page_shield_events','audit_logs','audit_logs_v2','gateway_dns','gateway_http','gateway_network','network_analytics_logs','access_requests','casb_findings','device_posture_results','dns_firewall_logs','magic_ids_detections','workers_trace_events','sinkhole_http_logs','zero_trust_network_sessions','websocket_analytics','zaraz_events','biso_user_actions','dex_application_tests','dex_device_state_events','dlp_forensic_copies','email_security_alerts','email_security_post_delivery_events','ipsec_logs','mcp_portal_logs','mnm_flow_logs','ssh_logs','turnstile_events','warp_config_changes','warp_toggle_changes']."
  }
}

variable "cloudflare_logpush_fields" {
  description = "The logpush dataset specific fields to log delimited with comma, leave empty to include all fields. the timestamp and its variants are included automatically."
  type        = list(string)
  default     = []
}

variable "cloudflare_zone_id" {
  description = "The cloudflare zone id for zone based data-sets"
  type        = string
  default     = ""
}

variable "cloudflare_account_id" {
  description = "The cloudflare account id for account based data-sets"
  type        = string
  default     = ""
}

variable "coralogix_application_name" {
  description = "The Coralogix Application Name for your logs"
  type        = string
  sensitive   = true
  default     = "cx-Cloudflare-Logpush-default-application"
}

variable "coralogix_subsystem_name" {
  description = "The Coralogix SubSystem Name for your logs"
  type        = string
  sensitive   = true
  default     = "cx-Cloudflare-Logpush-default-subsystem"
}

variable "cloudflare_account_filter" {
  description = "value to filter the account logs"
  type        = string
  default     = ""
}

variable "cloudflare_zone_filter" {
  description = "value to filter the zone logs"
  type        = string
  default     = ""
}

variable "cloudflare_account_sample_rate" {
  description = "The sample rate for account based data-sets"
  type        = number
  default     = 1
}

variable "cloudflare_zone_sample_rate" {
  description = "The sample rate for zone based data-sets"
  type        = number
  default     = 1
}

variable "max_upload_interval_seconds" {
  description = "The maximum interval in seconds for log batches"
  type        = number
  default     = null

  validation {
    condition     = var.max_upload_interval_seconds == null || (coalesce(var.max_upload_interval_seconds, 0) >= 30 && coalesce(var.max_upload_interval_seconds, 0) <= 300)
    error_message = "This setting must be between 30 and 300 seconds (5 minutes)"
  }
}


variable "custom_domain" {
  description = "Custom Coralogix domain, bare FQDN without the ingress. prefix (e.g. private.us1.coralogix.com). Required when coralogix_region = \"Custom\"."
  type        = string
  default     = null
  validation {
    condition     = var.coralogix_region != "Custom" || (var.custom_domain != null && var.custom_domain != "")
    error_message = "custom_domain is required when coralogix_region is \"Custom\"."
  }
}
