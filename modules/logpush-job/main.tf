locals {
  job_name = "Coralogix-${replace(var.cloudflare_logpush_dataset,"_","-")}-${random_string.this.result}"
  coralogix_regions = {
    Europe    = "ingress.coralogix.com"
    Europe2   = "ingress.eu2.coralogix.com"
    India     = "ingress.app.coralogix.in"
    Singapore = "ingress.coralogixsg.com"
    US        = "ingress.coralogix.us"
    US2       = "ingress.cx498.coralogix.com"
  }
  coralogix_dataset = {
    dns_logs = "DNSLogs"
    firewall_events = "FirewallEvents"
    http_requests = "HTTPRequests"
    nel_reports = "NELReports"
    spectrum_events = "SpectrumEvents"
    audit_logs = "AuditLogs"
    gateway_dns = "GatewayDNS"
    gateway_http = "GatewayHTTP"
    gateway_network = "GatewayNetwork"
    network_analytics_logs = "NetworkAnalyticsLogs"
    access_requests = "AccessRequests"
    casb_findings = "CASBFindings"
    device_posture_results = "DevicePostureResults"
    dns_firewall_logs = "DnsFirewallLogs"
    magic_ids_detections = "MagicIdsDetections"
    workers_trace_events = "WorkersTraceEvents"
    zero_trust_network_sessions = "ZeroTrustNetworkSessionLogs"
  }
    dataset_timestamp = {
    dns_logs = "Timestamp"
    firewall_events = "Datetime"
    http_requests = "EdgeStartTimestamp"
    nel_reports = "Timestamp"
    spectrum_events = "Timestamp"
    audit_logs = "When"
    gateway_dns = "Datetime"
    gateway_http = "Datetime"
    gateway_network = "Datetime"
    network_analytics_logs = "Datetime"
    access_requests = "CreatedAt"
    casb_findings = "DetectedTimestamp"
    device_posture_results = "Timestamp"
    dns_firewall_logs = "Timestamp"
    magic_ids_detections = "Timestamp"
    workers_trace_events = "EventTimestampMs"
    zero_trust_network_sessions = "SessionStartTime"
  }
  dataset_full_fields = {
    dns_logs = ["Timestamp", "ColoCode", "EDNSSubnet", "EDNSSubnetLength", "QueryName", "QueryType", "ResponseCached", "ResponseCode", "SourceIP"]
    firewall_events = ["Datetime", "Action", "ClientASN", "ClientASNDescription", "ClientCountry", "ClientIP", "ClientIPClass", "ClientRefererHost", "ClientRefererPath", "ClientRefererQuery", "ClientRefererScheme", "ClientRequestHost", "ClientRequestMethod", "ClientRequestPath", "ClientRequestProtocol", "ClientRequestQuery", "ClientRequestScheme", "ClientRequestUserAgent", "EdgeColoCode", "EdgeResponseStatus", "Kind", "MatchIndex", "Metadata", "OriginResponseStatus", "OriginatorRayID", "RayID", "RuleID", "Source"]
    http_requests = ["CacheCacheStatus", "CacheResponseBytes", "CacheResponseStatus", "CacheTieredFill", "ClientASN", "ClientCountry", "ClientDeviceType", "ClientIP", "ClientIPClass", "ClientMTLSAuthCertFingerprint", "ClientMTLSAuthStatus", "ClientRequestBytes", "ClientRequestHost", "ClientRequestMethod", "ClientRequestPath", "ClientRequestProtocol", "ClientRequestReferer", "ClientRequestScheme", "ClientRequestSource", "ClientRequestURI", "ClientRequestUserAgent", "ClientSSLCipher", "ClientSSLProtocol", "ClientSrcPort", "ClientTCPRTTMs", "ClientXRequestedWith", "EdgeCFConnectingO2O", "EdgeColoCode", "EdgeColoID", "EdgeEndTimestamp", "EdgeStartTimestamp", "EdgePathingOp", "EdgePathingSrc", "EdgePathingStatus", "EdgeRateLimitAction", "EdgeRateLimitID", "EdgeRequestHost", "EdgeResponseBodyBytes", "EdgeResponseBytes", "EdgeResponseCompressionRatio", "EdgeResponseContentType", "EdgeResponseStatus", "EdgeServerIP", "EdgeTimeToFirstByteMs", "FirewallMatchesActions", "FirewallMatchesRuleIDs", "FirewallMatchesSources", "OriginDNSResponseTimeMs", "OriginIP", "OriginRequestHeaderSendDurationMs", "OriginResponseBytes", "OriginResponseDurationMs", "OriginResponseHTTPExpires", "OriginResponseHTTPLastModified", "OriginResponseHeaderReceiveDurationMs", "OriginResponseStatus", "OriginResponseTime", "OriginSSLProtocol", "OriginTCPHandshakeDurationMs", "OriginTLSHandshakeDurationMs", "ParentRayID", "RayID", "RequestHeaders", "ResponseHeaders", "SecurityLevel", "SmartRouteColoID", "UpperTierColoID", "WAFAction", "WAFFlags", "WAFMatchedVar", "WAFProfile", "WAFRuleID", "WAFRuleMessage", "WorkerCPUTime", "WorkerStatus", "WorkerSubrequest", "WorkerSubrequestCount", "ZoneID", "ZoneName"]
    nel_reports = ["Timestamp", "ClientIPASN", "ClientIPASNDescription", "ClientIPCountry", "LastKnownGoodColoCode", "Phase", "Type"]
    spectrum_events = ["Timestamp", "Application", "ClientAsn", "ClientBytes", "ClientCountry", "ClientIP", "ClientMatchedIpFirewall", "ClientPort", "ClientProto", "ClientTcpRtt", "ClientTlsCipher", "ClientTlsClientHelloServerName", "ClientTlsProtocol", "ClientTlsStatus", "ColoCode", "ConnectTimestamp", "DisconnectTimestamp", "Event", "IpFirewall", "OriginBytes", "OriginIP", "OriginPort", "OriginProto", "OriginTcpRtt", "OriginTlsCipher", "OriginTlsFingerprint", "OriginTlsMode", "OriginTlsProtocol", "OriginTlsStatus", "ProxyProtocol", "Status"]
    audit_logs = ["When", "ActionResult", "ActionType", "ActorEmail", "ActorID", "ActorIP", "ActorType", "ID", "Interface", "Metadata", "NewValue", "OldValue", "OwnerID", "ResourceID", "ResourceType"]
    gateway_dns = ["Datetime", "ColoID", "ColoName", "DeviceID", "DstIP", "DstPort", "Email", "Location", "MatchedCategoryIDs", "Policy", "PolicyID", "Protocol", "QueryCategoryIDs", "QueryName", "QueryNameReversed", "QuerySize", "QueryType", "RData", "ResolverDecision", "SrcIP", "SrcPort", "UserID"]
    gateway_http = ["Datetime", "AccountID", "Action", "BlockedFileHash", "BlockedFileName", "BlockedFileReason", "BlockedFileSize", "BlockedFileType", "DestinationIP", "DestinationPort", "DeviceID", "DownloadedFileNames", "Email", "HTTPHost", "HTTPMethod", "HTTPVersion", "IsIsolated", "PolicyID", "Referer", "RequestID", "SourceIP", "SourcePort", "URL", "UploadedFileNames", "UserAgent", "UserID"]
    gateway_network = ["Datetime", "AccountID", "Action", "DestinationIP", "DestinationPort", "DeviceID", "Email", "OverrideIP", "OverridePort", "PolicyID", "SNI", "SessionID", "SourceIP", "SourcePort", "Transport", "UserID"]
    network_analytics_logs = ["Datetime", "AttackCampaignID", "AttackID", "ColoCountry", "ColoGeoHash", "ColoID", "ColoName", "DestinationASN", "DestinationASNDescription", "DestinationCountry", "DestinationGeoHash", "DestinationPort", "Direction", "GREChecksum", "GREEthertype", "GREHeaderLength", "GREKey", "GRESequenceNumber", "GREVersion", "ICMPChecksum", "ICMPCode", "ICMPType", "IPDestinationAddress", "IPDestinationSubnet", "IPFragmentOffset", "IPHeaderLength", "IPMoreFragments", "IPProtocol", "IPProtocolName", "IPSourceAddress", "IPSourceSubnet", "IPTotalLength", "IPTotalLengthBuckets", "IPTtl", "IPTtlBuckets", "IPv4Checksum", "IPv4DontFragment", "IPv4Dscp", "IPv4Ecn", "IPv4Identification", "IPv4Options", "IPv6Dscp", "IPv6Ecn", "IPv6ExtensionHeaders", "IPv6FlowLabel", "IPv6Identification", "MitigationReason", "MitigationScope", "MitigationSystem", "ProtocolState", "RuleID", "RulesetID", "RulesetOverrideID", "SampleInterval", "SourceASN", "SourceASNDescription", "SourceCountry", "SourceGeoHash", "SourcePort", "TCPAcknowledgementNumber", "TCPChecksum", "TCPDataOffset", "TCPFlags", "TCPFlagsString", "TCPMss", "TCPOptions", "TCPSackBlocks", "TCPSacksPermitted", "TCPSequenceNumber", "TCPTimestampEcr", "TCPTimestampValue", "TCPUrgentPointer", "TCPWindowScale", "TCPWindowSize", "UDPChecksum", "UDPPayloadLength", "Verdict"]
    access_requests = ["CreatedAt", "Action", "Allowed", "AppDomain", "AppUUID", "Connection", "Country", "Email", "IPAddress", "PurposeJustificationPrompt", "PurposeJustificationResponse", "RayID", "TemporaryAccessApprovers", "TemporaryAccessDuration", "UserUID"]
    casb_findings = ["DetectedTimestamp", "AssetDisplayName", "AssetExternalID", "AssetLink", "AssetMetadata", "FindingTypeDisplayName", "FindingTypeID", "FindingTypeSeverity", "InstanceID", "IntegrationDisplayName", "IntegrationID", "IntegrationPolicyVendor"]
    device_posture_results = ["Timestamp", "ClientVersion", "DeviceID", "DeviceManufacturer", "DeviceModel", "DeviceName", "DeviceSerialNumber", "DeviceType", "Email", "OSVersion", "PolicyID", "PostureCheckName", "PostureCheckType", "PostureEvaluatedResult", "PostureExpectedJSON", "PostureReceivedJSON", "UserUID"]
    dns_firewall_logs = ["Timestamp", "ClientResponseCode", "ClusterID", "ColoCode", "EDNSSubnet", "EDNSSubnetLength", "QueryDO", "QueryName", "QueryRD", "QuerySize", "QueryTCP", "QueryType", "ResponseCached", "ResponseCachedStale", "SourceIP", "UpstreamIP", "UpstreamResponseCode", "UpstreamResponseTimeMs"]
    magic_ids_detections = ["Timestamp", "Action", "ColoCity", "ColoCode", "DestinationIP", "DestinationPort", "Protocol", "SignatureID", "SignatureMessage", "SignatureRevision", "SourceIP", "SourcePort"]
    workers_trace_events = ["EventTimestampMs", "DispatchNamespace", "Event", "EventType", "Exceptions", "Logs", "Outcome", "ScriptName", "ScriptTags"]
    zero_trust_network_sessions = ["SessionStartTime", "AccountID", "BytesReceived", "BytesSent", "ClientTCPHandshakeDurationMs", "ClientTLSCipher", "ClientTLSHandshakeDurationMs", "ClientTLSVersion", "ConnectionCloseReason", "ConnectionReuse", "DestinationTunnelID", "DeviceID", "DeviceName", "EgressColoName", "EgressIP", "EgressPort", "EgressRuleID", "EgressRuleName", "Email", "IngressColoName", "Offramp", "OriginIP", "OriginPort", "OriginTLSCertificateIssuer", "OriginTLSCertificateValidationResult", "OriginTLSCipher", "OriginTLSHandshakeDurationMs", "OriginTLSVersion", "Protocol", "RuleEvaluationDurationMs", "SessionEndTime", "SessionID", "SessionStartTime", "SessionStatus", "SessionType", "SourceIP", "SourcePort", "UserAgent", "UserID", "VirtualNetworkID"]
  }
  dataset_type = {
    dns_logs = "zone"
    firewall_events = "zone"
    http_requests = "zone"
    nel_reports = "zone"
    spectrum_events = "zone"
    audit_logs = "account"
    gateway_dns = "account"
    gateway_http = "account"
    gateway_network = "account"
    network_analytics_logs = "account"
    access_requests = "account"
    casb_findings = "account"
    device_posture_results = "account"
    dns_firewall_logs = "account"
    magic_ids_detections = "account"
    workers_trace_events = "account"
    zero_trust_network_sessions = "account"
  }

}
resource "random_string" "this" {
  length  = 6
  special = false
  lower = true
  upper = false
}

resource "cloudflare_logpush_job" "crx-logpush-zone" {
  count = local.dataset_type[var.cloudflare_logpush_dataset] == "zone" ? 1 : 0
  enabled             = true
  zone_id = var.cloudflare_zone_id
  name                = local.job_name
  destination_conf = var.coralogix_subsystem_name != "" || var.coralogix_application_name != "" ? "https://${local.coralogix_regions[var.coralogix_region]}/cloudflare/v1/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_CX-Application-Name=${var.coralogix_application_name}&header_CX-Subsystem-Name=${var.coralogix_subsystem_name}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}" : "https://${local.coralogix_regions[var.coralogix_region]}/cloudflare/v1/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}"
  dataset             = var.cloudflare_logpush_dataset
  frequency = "low"
  filter = var.cloudflare_zone_filter
  ownership_challenge = ""
  kind = ""
  output_options {
    field_names = coalesce(var.cloudflare_logpush_fields,local.dataset_full_fields[var.cloudflare_logpush_dataset])
    timestamp_format = "unixnano"
    sample_rate = var.cloudflare_zone_sample_rate
  }
  lifecycle {
  }
}

resource "cloudflare_logpush_job" "crx-logpush-account" {
  count = local.dataset_type[var.cloudflare_logpush_dataset] == "account" ? 1 : 0 
  enabled             = true
  account_id = var.cloudflare_account_id
  name                = local.job_name
  destination_conf = var.coralogix_subsystem_name != "" || var.coralogix_application_name != "" ? "https://${local.coralogix_regions[var.coralogix_region]}/cloudflare/v1/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_CX-Application-Name=${var.coralogix_application_name}&header_CX-Subsystem-Name=${var.coralogix_subsystem_name}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}" : "https://${local.coralogix_regions[var.coralogix_region]}/api/v1/cloudflare/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}"
  dataset             = var.cloudflare_logpush_dataset
  frequency = "low"
  filter = var.cloudflare_account_filter
  ownership_challenge = ""
  kind = ""
  output_options {
    field_names = coalesce(var.cloudflare_logpush_fields,local.dataset_full_fields[var.cloudflare_logpush_dataset])
    timestamp_format = "unixnano"
    sample_rate = var.cloudflare_account_sample_rate
  }
  lifecycle {
  }
}
