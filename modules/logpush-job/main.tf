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
    page_shield_events = "PageShieldEvents"
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
    sinkhole_http_logs = "SinkholeHTTPLogs"
    zero_trust_network_sessions = "ZeroTrustNetworkSessionLogs"
  }
    dataset_timestamp = {
    dns_logs = "Timestamp"
    firewall_events = "Datetime"
    http_requests = "EdgeStartTimestamp"
    nel_reports = "Timestamp"
    spectrum_events = "Timestamp"
    page_shield_events = "Timestamp"
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
    sinkhole_http_logs = "Timestamp"
    zero_trust_network_sessions = "SessionStartTime"
  }

  
  dataset_full_fields = {
    dns_logs = ["Timestamp", "ColoCode", "EDNSSubnet", "EDNSSubnetLength", "QueryName", "QueryType", "ResponseCached", "ResponseCode", "SourceIP"]
    firewall_events = ["Action", "ClientASN", "ClientASNDescription", "ClientCountry", "ClientIP", "ClientIPClass", "ClientRefererHost", "ClientRefererPath", "ClientRefererQuery", "ClientRefererScheme", "ClientRequestHost", "ClientRequestMethod", "ClientRequestPath", "ClientRequestProtocol", "ClientRequestQuery", "ClientRequestScheme", "ClientRequestUserAgent", "ContentScanObjResults", "ContentScanObjSizes", "ContentScanObjTypes", "Datetime", "Description", "EdgeColoCode", "EdgeResponseStatus", "Kind", "LeakedCredentialCheckResult", "MatchIndex", "Metadata", "OriginResponseStatus", "OriginatorRayID", "RayID", "Ref", "RuleID", "Source"]
    http_requests = ["BotDetectionIDs", "BotDetectionTags", "BotScore", "BotScoreSrc", "BotTags", "CacheCacheStatus", "CacheReserveUsed", "CacheResponseBytes", "CacheTieredFill", "ClientASN", "ClientCountry", "ClientDeviceType", "ClientIP", "ClientIPClass", "ClientMTLSAuthCertFingerprint", "ClientMTLSAuthStatus", "ClientRegionCode", "ClientRequestBytes", "ClientRequestHost", "ClientRequestMethod", "ClientRequestPath", "ClientRequestProtocol", "ClientRequestReferer", "ClientRequestScheme", "ClientRequestSource", "ClientRequestURI", "ClientRequestUserAgent", "ClientSSLCipher", "ClientSSLProtocol", "ClientSrcPort", "ClientTCPRTTMs", "ClientXRequestedWith", "ContentScanObjResults", "ContentScanObjSizes", "ContentScanObjTypes", "Cookies", "EdgeCFConnectingO2O", "EdgeColoCode", "EdgeColoID", "EdgeEndTimestamp", "EdgePathingOp", "EdgePathingSrc", "EdgePathingStatus", "EdgeRequestHost", "EdgeResponseBodyBytes", "EdgeResponseBytes", "EdgeResponseCompressionRatio", "EdgeResponseContentType", "EdgeResponseStatus", "EdgeServerIP", "EdgeStartTimestamp", "EdgeTimeToFirstByteMs", "JA3Hash", "JA4", "JA4Signals", "LeakedCredentialCheckResult", "OriginDNSResponseTimeMs", "OriginIP", "OriginRequestHeaderSendDurationMs",  "OriginResponseDurationMs", "OriginResponseHTTPExpires", "OriginResponseHTTPLastModified", "OriginResponseHeaderReceiveDurationMs", "OriginResponseStatus",  "OriginSSLProtocol", "OriginTCPHandshakeDurationMs", "OriginTLSHandshakeDurationMs", "ParentRayID", "RayID", "RequestHeaders", "ResponseHeaders", "SecurityAction", "SecurityActions", "SecurityRuleDescription", "SecurityRuleID", "SecurityRuleIDs", "SecuritySources", "SmartRouteColoID", "UpperTierColoID", "WAFAttackScore",  "WAFRCEAttackScore", "WAFSQLiAttackScore", "WAFXSSAttackScore", "WorkerCPUTime", "WorkerStatus", "WorkerSubrequest", "WorkerSubrequestCount", "WorkerWallTimeUs", "ZoneName"]
    nel_reports = ["ClientIPASN", "ClientIPASNDescription", "ClientIPCountry", "LastKnownGoodColoCode", "Phase", "Timestamp", "Type"]
    spectrum_events = ["Application", "ClientAsn", "ClientBytes", "ClientCountry", "ClientIP", "ClientMatchedIpFirewall", "ClientPort", "ClientProto", "ClientTcpRtt", "ClientTlsCipher", "ClientTlsClientHelloServerName", "ClientTlsProtocol", "ClientTlsStatus", "ColoCode", "ConnectTimestamp", "DisconnectTimestamp", "Event", "IpFirewall", "OriginBytes", "OriginIP", "OriginPort", "OriginProto", "OriginTcpRtt", "OriginTlsCipher", "OriginTlsFingerprint", "OriginTlsMode", "OriginTlsProtocol", "OriginTlsStatus", "ProxyProtocol", "Status", "Timestamp"]
    page_shield_events = ["Action", "Host", "PageURL", "PolicyID", "Timestamp", "URL", "URLContainsCDNCGIPath", "URLHost"]
    audit_logs = ["ActionResult", "ActionType", "ActorEmail", "ActorID", "ActorIP", "ActorType", "ID", "Interface", "Metadata", "NewValue", "OldValue", "OwnerID", "ResourceID", "ResourceType", "When"]
    gateway_dns = ["ApplicationID", "CNAMECategoryIDs", "CNAMECategoryNames", "ColoCode", "ColoID", "CustomResolveDurationMs", "CustomResolverAddress", "CustomResolverPolicyID", "CustomResolverPolicyName", "CustomResolverResponse", "Datetime", "DeviceID", "DeviceName", "DstIP", "DstPort", "Email", "InitialCategoryIDs", "InitialCategoryNames", "IsResponseCached", "Location", "LocationID", "MatchedCategoryIDs", "MatchedCategoryNames", "MatchedIndicatorFeedIDs", "MatchedIndicatorFeedNames", "Policy", "PolicyID", "Protocol", "QueryCategoryIDs", "QueryCategoryNames", "QueryIndicatorFeedIDs", "QueryIndicatorFeedNames", "QueryName", "QueryNameReversed", "QuerySize", "QueryType", "QueryTypeName", "RCode", "RData", "ResolvedIPCategoryIDs", "ResolvedIPCategoryNames", "ResolvedIPs", "ResolverDecision", "SrcIP", "SrcPort", "TimeZone", "TimeZoneInferredMethod", "UserID"]
    gateway_http = ["AccountID", "Action", "BlockedFileHash", "BlockedFileName", "BlockedFileReason", "BlockedFileSize", "BlockedFileType", "Datetime", "DestinationIP", "DestinationPort", "DeviceID", "DeviceName", "DownloadMatchedDlpProfileEntries", "DownloadMatchedDlpProfiles", "DownloadedFileNames", "Email", "FileInfo", "HTTPHost", "HTTPMethod", "HTTPStatusCode", "HTTPVersion", "IsIsolated", "PolicyID", "PolicyName", "Referer", "RequestID", "SessionID", "SourceIP", "SourceInternalIP", "SourcePort", "URL", "UntrustedCertificateAction", "UploadMatchedDlpProfileEntries", "UploadMatchedDlpProfiles", "UploadedFileNames", "UserAgent", "UserID"]
    gateway_network = ["AccountID", "Action", "Datetime", "DestinationIP", "DestinationPort", "DetectedProtocol", "DeviceID", "DeviceName", "Email", "OverrideIP", "OverridePort", "PolicyID", "PolicyName", "SNI", "SessionID", "SourceIP", "SourceInternalIP", "SourcePort", "Transport", "UserID"]
    network_analytics_logs = ["AttackCampaignID", "AttackID", "AttackVector", "ColoCity", "ColoCode", "ColoCountry", "ColoGeoHash", "ColoName", "Datetime", "DestinationASN", "DestinationASNName", "DestinationCountry", "DestinationGeoHash", "DestinationPort", "Direction", "GREChecksum", "GREEtherType", "GREHeaderLength", "GREKey", "GRESequenceNumber", "GREVersion", "ICMPChecksum", "ICMPCode", "ICMPType", "IPDestinationAddress", "IPDestinationSubnet", "IPFragmentOffset", "IPHeaderLength", "IPMoreFragments", "IPProtocol", "IPProtocolName", "IPSourceAddress", "IPSourceSubnet", "IPTTL", "IPTTLBuckets", "IPTotalLength", "IPTotalLengthBuckets", "IPv4Checksum", "IPv4DSCP", "IPv4DontFragment", "IPv4ECN", "IPv4Identification", "IPv4Options", "IPv6DSCP", "IPv6ECN", "IPv6ExtensionHeaders", "IPv6FlowLabel", "IPv6Identification", "MitigationReason", "MitigationScope", "MitigationSystem", "Outcome", "ProtocolState", "RuleID", "RuleName", "RulesetID", "RulesetOverrideID", "SampleInterval", "SourceASN", "SourceASNName", "SourceCountry", "SourceGeoHash", "SourcePort", "TCPAcknowledgementNumber", "TCPChecksum", "TCPDataOffset", "TCPFlags", "TCPFlagsString", "TCPMSS", "TCPOptions", "TCPSACKBlocks", "TCPSACKPermitted", "TCPSequenceNumber", "TCPTimestampECR", "TCPTimestampValue", "TCPUrgentPointer", "TCPWindowScale", "TCPWindowSize", "UDPChecksum", "UDPPayloadLength", "Verdict"]
    access_requests = ["Action", "Allowed", "AppDomain", "AppUUID", "Connection", "Country", "CreatedAt", "Email", "IPAddress", "PurposeJustificationPrompt", "PurposeJustificationResponse", "RayID", "TemporaryAccessApprovers", "TemporaryAccessDuration", "UserUID"]
    casb_findings = ["AssetDisplayName", "AssetExternalID", "AssetLink", "AssetMetadata", "DetectedTimestamp", "FindingTypeDisplayName", "FindingTypeID", "FindingTypeSeverity", "InstanceID", "IntegrationDisplayName", "IntegrationID", "IntegrationPolicyVendor"]
    device_posture_results = ["ClientVersion", "DeviceID", "DeviceManufacturer", "DeviceModel", "DeviceName", "DeviceSerialNumber", "DeviceType", "Email", "OSVersion", "PolicyID", "PostureCheckName", "PostureCheckType", "PostureEvaluatedResult", "PostureExpectedJSON", "PostureReceivedJSON", "Timestamp", "UserUID"]
    dns_firewall_logs = ["ClientResponseCode", "ClusterID", "ColoCode", "EDNSSubnet", "EDNSSubnetLength", "QueryDO", "QueryName", "QueryRD", "QuerySize", "QueryTCP", "QueryType", "ResponseCached", "ResponseCachedStale", "ResponseReason", "SourceIP", "Timestamp", "UpstreamIP", "UpstreamResponseCode", "UpstreamResponseTimeMs"]
    magic_ids_detections = ["Action", "ColoCity", "ColoCode", "DestinationIP", "DestinationPort", "Protocol", "SignatureID", "SignatureMessage", "SignatureRevision", "SourceIP", "SourcePort", "Timestamp"]
    sinkhole_http_logs = ["AccountID", "Body", "BodyLength", "DestAddr", "Headers", "Host", "Method", "Password", "R2Path", "Referrer", "SinkholeID", "SrcAddr", "Timestamp", "URI", "URL", "UserAgent", "Username"]
    workers_trace_events = ["DispatchNamespace", "Entrypoint", "Event", "EventTimestampMs", "EventType", "Exceptions", "Logs", "Outcome", "ScriptName", "ScriptTags", "ScriptVersion"]
    zero_trust_network_sessions = ["AccountID", "BytesReceived", "BytesSent", "ClientTCPHandshakeDurationMs", "ClientTLSCipher", "ClientTLSHandshakeDurationMs", "ClientTLSVersion", "ConnectionCloseReason", "ConnectionReuse", "DestinationTunnelID", "DetectedProtocol", "DeviceID", "DeviceName", "EgressColoName", "EgressIP", "EgressPort", "EgressRuleID", "EgressRuleName", "Email", "IngressColoName", "Offramp", "OriginIP", "OriginPort", "OriginTLSCertificateIssuer", "OriginTLSCertificateValidationResult", "OriginTLSCipher", "OriginTLSHandshakeDurationMs", "OriginTLSVersion", "Protocol", "RuleEvaluationDurationMs", "SessionEndTime", "SessionID", "SessionStartTime", "SourceIP", "SourceInternalIP", "SourcePort", "UserID", "VirtualNetworkID"]
  }
  dataset_type = {
    dns_logs = "zone"
    firewall_events = "zone"
    http_requests = "zone"
    nel_reports = "zone"
    spectrum_events = "zone"
    page_shield_events = "zone"
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
    sinkhole_http_logs = "account"
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
    field_names = coalescelist(var.cloudflare_logpush_fields,local.dataset_full_fields[var.cloudflare_logpush_dataset])
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
    field_names = coalescelist(var.cloudflare_logpush_fields,local.dataset_full_fields[var.cloudflare_logpush_dataset])
    timestamp_format = "unixnano"
    sample_rate = var.cloudflare_account_sample_rate
  }
  lifecycle {
  }
}
