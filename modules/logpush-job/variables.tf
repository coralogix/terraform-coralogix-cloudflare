variable "coralogix_region" {
  description = "The Coralogix location region, possible options are [EU1, EU2, AP1, AP2, US1, US2, AP3]"
  type        = string
  default     = "EU1"
    validation {
    condition = contains(["Europe","Europe2","India","Singapore","US","US2","AP3","EU1","EU2","AP1","Ap2","US2"], var.coralogix_region)
    error_message = "The coralogix region must be on of these values: [Europe, Europe2, India, Singapore, US, US2, AP3, EU1, EU2, AP1, AP2, US1]."
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
  validation {
    condition = contains(["dns_logs","firewall_events","http_requests","nel_reports","spectrum_events","page_shield_events", "audit_logs","gateway_dns","gateway_http","gateway_network","network_analytics_logs","access_requests","casb_findings","device_posture_results","dns_firewall_logs","magic_ids_detections","workers_trace_events","zero_trust_network_sessions", "sinkhole_http_logs"], var.cloudflare_logpush_dataset)
    error_message = "Logpush dataset must be one of these values: ['dns_logs','firewall_events','http_requests','nel_reports','spectrum_events','audit_logs','gateway_dns','gateway_http','gateway_network','network_analytics_logs','access_requests','casb_findings','device_posture_results','dns_firewall_logs','magic_ids_detections','workers_trace_events','zero_trust_network_sessions']."
  }
}

variable "cloudflare_logpush_fields" {
  description = "The logpush dataset specific fields to log delimited with comma, leave empty to include all fields. the timestamp and its variants are included automatically."
  type        = list(string)
  default     = []
}

variable "cloudflare_zone_id" {
  description = "The cloudflare zone id for zone based data-sets"
  type = string
  default = ""
}

variable "cloudflare_account_id" {
  description = "The cloudflare account id for account based data-sets"
  type = string
  default = ""
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
