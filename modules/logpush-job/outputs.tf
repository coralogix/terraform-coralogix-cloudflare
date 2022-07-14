output "logpush_job_name" {
  description = "The name of the logpush job"
  value       = local.dataset_type[var.cloudflare_logpush_dataset] == "zone" ? cloudflare_logpush_job.crx-logpush-zone[0].name : cloudflare_logpush_job.crx-logpush-account[0].name
}

output "logpush_job_scope" {
  description = "The scope of the logpush job"
  value       = local.dataset_type[var.cloudflare_logpush_dataset] == "zone" ? "Zone" : "Account"
}
