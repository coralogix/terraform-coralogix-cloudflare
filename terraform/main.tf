data "aws_secretsmanager_secret" "secrets" {
  arn = "arn:aws:secretsmanager:eu-west-1:529726762838:secret:static/secrets-gdjD9O"
  provider = aws.secrets
}

data "aws_secretsmanager_secret_version" "version" {
  secret_id = data.aws_secretsmanager_secret.secrets.id
  provider = aws.secrets
}

locals {
  c4c_private_key = jsondecode(data.aws_secretsmanager_secret_version.version.secret_string)["monitoring"]["coralogix-privatekey"]["audit"]
}


module "logpush-job" {
    source = "coralogix/cloudflare/coralogix//modules/logpush-job"

    coralogix_region   = "Europe2"
    coralogix_private_key = local.c4c_private_key
    cloudflare_logpush_dataset = "http_requests"
    cloudflare_logpush_fields = "RayID,ClientSSLProtocol,ClientRequestBytes,ClientASN,ClientCountry,ClientDeviceType,ClientIP,ClientIPClass,ClientRequestHost,ClientRequestMethod,ClientRequestPath,ClientRequestProtocol,ClientRequestReferer,ClientRequestURI,ClientRequestUserAgent,EdgeEndTimestamp,EdgeResponseBytes,EdgeResponseStatus,EdgeStartTimestamp,FirewallMatchesActions,FirewallMatchesRuleIDs,FirewallMatchesSources,OriginDNSResponseTimeMs,OriginIP,OriginSSLProtocol,OriginResponseStatus,OriginResponseTime,WAFAction,WAFFlags,WAFMatchedVar,WAFProfile,WAFRuleID,WAFRuleMessage" # empty for all fields
    cloudflare_zone_id = var.cx_foundation.vars.CX_CLOUDFLARE_SITE_ID
    cloudflare_account_id = "178368581027f2ab845898d7ad9e1561" # to be used with account-scoped datasets
}
