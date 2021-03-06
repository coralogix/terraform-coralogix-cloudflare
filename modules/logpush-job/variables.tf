variable "coralogix_region" {
  description = "The Coralogix location region, possible options are [Europe, Europe2, India, Singapore, US]"
  type        = string
  default     = "Europe"
    validation {
    condition = contains(["Europe","Europe2","India","Singapore","US"], var.coralogix_region)
    error_message = "The coralogix region must be on of these values: [Europe, Europe2, India, Singapore, US]."
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
    condition = contains(["dns_logs","firewall_events","http_requests","nel_reports","spectrum_events","audit_logs","gateway_dns","gateway_http","gateway_network","network_analytics_logs"], var.cloudflare_logpush_dataset)
    error_message = "Logpush dataset must be one of these values: ['dns_logs','firewall_events','http_requests','nel_reports','spectrum_events','audit_logs','gateway_dns','gateway_http','gateway_network','network_analytics_logs']."
  }
}

variable "cloudflare_logpush_fields" {
  description = "The logpush dataset specific fields to log delimited with comma, leave empty to include all fields. the timestamp and its variants are included automatically."
  type        = string
  default = ""
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