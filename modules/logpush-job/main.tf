locals {
  job_name = "Coralogix-${replace(var.cloudflare_logpush_dataset,"_","-")}-${random_string.this.result}"
  coralogix_regions = {
    Europe    = "cdn-ingress.coralogix.com"
    Europe2   = "cdn-ingress.eu2.coralogix.com"
    India     = "cdn-ingress.app.coralogix.in"
    Singapore = "cdn-ingress.coralogixsg.com"
    US        = "cdn-ingress.coralogix.us"
    US2       = "cdn-ingress.cx498.coralogix.com"
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
    dns_logs = "ColoCode,EDNSSubnet,EDNSSubnetLength,QueryName,QueryType,ResponseCached,ResponseCode,SourceIP"
    firewall_events = "Action,ClientASN,ClientASNDescription,ClientCountry,ClientIP,ClientIPClass,ClientRefererHost,ClientRefererPath,ClientRefererQuery,ClientRefererScheme,ClientRequestHost,ClientRequestMethod,ClientRequestPath,ClientRequestProtocol,ClientRequestQuery,ClientRequestScheme,ClientRequestUserAgent,EdgeColoCode,EdgeResponseStatus,Kind,MatchIndex,Metadata,OriginResponseStatus,OriginatorRayID,RayID,RuleID,Source"
    http_requests = "BotScoreCloudflare,BotScoreSrc,BotTags,CacheCacheStatus,CacheResponseBytes,CacheResponseStatus,CacheTieredFill,ClientASN,ClientCountry,ClientDeviceType,ClientIP,ClientIPClass,ClientMTLSAuthCertFingerprint,ClientMTLSAuthStatus,ClientRequestBytes,ClientRequestHost,ClientRequestMethod,ClientRequestPath,ClientRequestProtocol,ClientRequestReferer,ClientRequestScheme,ClientRequestSource,ClientRequestURI,ClientRequestUserAgent,ClientSSLCipher,ClientSSLProtocol,ClientSrcPort,ClientTCPRTTMs,ClientXRequestedWith,EdgeCFConnectingO2O,EdgeColoCode,EdgeColoID,EdgeEndTimestamp,EdgePathingOp,EdgePathingSrc,EdgePathingStatus,EdgeRateLimitAction,EdgeRateLimitID,EdgeRequestHost,EdgeResponseBodyBytes,EdgeResponseBytes,EdgeResponseCompressionRatio,EdgeResponseContentType,EdgeResponseStatus,EdgeServerIP,EdgeTimeToFirstByteMs,FirewallMatchesActions,FirewallMatchesRuleIDs,FirewallMatchesSources,JA3Hash,OriginDNSResponseTimeMs,OriginIP,OriginRequestHeaderSendDurationMs,OriginResponseBytes,OriginResponseDurationMs,OriginResponseHTTPExpires,OriginResponseHTTPLastModified,OriginResponseHeaderReceiveDurationMs,OriginResponseStatus,OriginResponseTime,OriginSSLProtocol,OriginTCPHandshakeDurationMs,OriginTLSHandshakeDurationMs,ParentRayID,RayID,RequestHeaders,ResponseHeaders,SecurityLevel,SmartRouteColoID,UpperTierColoID,WAFAction,WAFFlags,WAFMatchedVar,WAFProfile,WAFRuleID,WAFRuleMessage,WorkerCPUTime,WorkerStatus,WorkerSubrequest,WorkerSubrequestCount,ZoneID,ZoneName"
    nel_reports = "ClientIPASN,ClientIPASNDescription,ClientIPCountry,LastKnownGoodColoCode,Phase,Type"
    spectrum_events = "Application,ClientAsn,ClientBytes,ClientCountry,ClientIP,ClientMatchedIpFirewall,ClientPort,ClientProto,ClientTcpRtt,ClientTlsCipher,ClientTlsClientHelloServerName,ClientTlsProtocol,ClientTlsStatus,ColoCode,ConnectTimestamp,DisconnectTimestamp,Event,IpFirewall,OriginBytes,OriginIP,OriginPort,OriginProto,OriginTcpRtt,OriginTlsCipher,OriginTlsFingerprint,OriginTlsMode,OriginTlsProtocol,OriginTlsStatus,ProxyProtocol,Status"
    audit_logs = "ActionResult,ActionType,ActorEmail,ActorID,ActorIP,ActorType,ID,Interface,Metadata,NewValue,OldValue,OwnerID,ResourceID,ResourceType"
    gateway_dns = "ColoID,ColoName,DeviceID,DstIP,DstPort,Email,Location,MatchedCategoryIDs,Policy,PolicyID,Protocol,QueryCategoryIDs,QueryName,QueryNameReversed,QuerySize,QueryType,RData,ResolverDecision,SrcIP,SrcPort,UserID"
    gateway_http = "AccountID,Action,BlockedFileHash,BlockedFileName,BlockedFileReason,BlockedFileSize,BlockedFileType,DestinationIP,DestinationPort,DeviceID,DownloadedFileNames,Email,HTTPHost,HTTPMethod,HTTPVersion,IsIsolated,PolicyID,Referer,RequestID,SourceIP,SourcePort,URL,UploadedFileNames,UserAgent,UserID"
    gateway_network = "AccountID,Action,DestinationIP,DestinationPort,DeviceID,Email,OverrideIP,OverridePort,PolicyID,SNI,SessionID,SourceIP,SourcePort,Transport,UserID"
    network_analytics_logs = "AttackCampaignID,AttackID,ColoCountry,ColoGeoHash,ColoID,ColoName,DestinationASN,DestinationASNDescription,DestinationCountry,DestinationGeoHash,DestinationPort,Direction,GREChecksum,GREEthertype,GREHeaderLength,GREKey,GRESequenceNumber,GREVersion,ICMPChecksum,ICMPCode,ICMPType,IPDestinationAddress,IPDestinationSubnet,IPFragmentOffset,IPHeaderLength,IPMoreFragments,IPProtocol,IPProtocolName,IPSourceAddress,IPSourceSubnet,IPTotalLength,IPTotalLengthBuckets,IPTtl,IPTtlBuckets,IPv4Checksum,IPv4DontFragment,IPv4Dscp,IPv4Ecn,IPv4Identification,IPv4Options,IPv6Dscp,IPv6Ecn,IPv6ExtensionHeaders,IPv6FlowLabel,IPv6Identification,MitigationReason,MitigationScope,MitigationSystem,ProtocolState,RuleID,RulesetID,RulesetOverrideID,SampleInterval,SourceASN,SourceASNDescription,SourceCountry,SourceGeoHash,SourcePort,TCPAcknowledgementNumber,TCPChecksum,TCPDataOffset,TCPFlags,TCPFlagsString,TCPMss,TCPOptions,TCPSackBlocks,TCPSacksPermitted,TCPSequenceNumber,TCPTimestampEcr,TCPTimestampValue,TCPUrgentPointer,TCPWindowScale,TCPWindowSize,UDPChecksum,UDPPayloadLength,Verdict"
    access_requests = "Action,Allowed,AppDomain,AppUUID,Connection,Country,Email,IPAddress,PurposeJustificationPrompt,PurposeJustificationResponse,RayID,TemporaryAccessApprovers,TemporaryAccessDuration,UserUID"
    casb_findings = "AssetDisplayName,AssetExternalID,AssetLink,AssetMetadata,FindingTypeDisplayName,FindingTypeID,FindingTypeSeverity,InstanceID,IntegrationDisplayName,IntegrationID,IntegrationPolicyVendor"
    device_posture_results = "ClientVersion,DeviceID,DeviceManufacturer,DeviceModel,DeviceName,DeviceSerialNumber,DeviceType,Email,OSVersion,PolicyID,PostureCheckName,PostureCheckType,PostureEvaluatedResult,PostureExpectedJSON,PostureReceivedJSON,UserUID"
    dns_firewall_logs = "ClientResponseCode,ClusterID,ColoCode,EDNSSubnet,EDNSSubnetLength,QueryDO,QueryName,QueryRD,QuerySize,QueryTCP,QueryType,ResponseCached,ResponseCachedStale,SourceIP,UpstreamIP,UpstreamResponseCode,UpstreamResponseTimeMs"
    magic_ids_detections = "Action,ColoCity,ColoCode,DestinationIP,DestinationPort,Protocol,SignatureID,SignatureMessage,SignatureRevision,SourceIP,SourcePort"
    workers_trace_events = "DispatchNamespace,Event,EventType,Exceptions,Logs,Outcome,ScriptName,ScriptTags"
    zero_trust_network_sessions = "AccountID,BytesReceived,BytesSent,ClientTCPHandshakeDurationMs,ClientTLSCipher,ClientTLSHandshakeDurationMs,ClientTLSVersion,ConnectionCloseReason,ConnectionReuse,DestinationTunnelID,DeviceID,DeviceName,EgressColoName,EgressIP,EgressPort,EgressRuleID,EgressRuleName,Email,IngressColoName,Offramp,OriginIP,OriginPort,OriginTLSCertificateIssuer,OriginTLSCertificateValidationResult,OriginTLSCipher,OriginTLSHandshakeDurationMs,OriginTLSVersion,Protocol,RuleEvaluationDurationMs,SessionEndTime,SessionID,SourceIP,SourceInternalIP,SourcePort,UserID,VirtualNetworkID"
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
  logpull_options     = "fields=${coalesce(var.cloudflare_logpush_fields,local.dataset_full_fields[var.cloudflare_logpush_dataset])},${local.dataset_timestamp[var.cloudflare_logpush_dataset]}&timestamps=unixnano"
  destination_conf = var.coralogix_subsystem_name != "" || var.coralogix_application_name != "" ? "https://${local.coralogix_regions[var.coralogix_region]}/api/v1/cloudflare/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_CX-Application-Name=${var.coralogix_application_name}&header_CX-Subsystem-Name=${var.coralogix_subsystem_name}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}" : "https://${local.coralogix_regions[var.coralogix_region]}/api/v1/cloudflare/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}"
  dataset             = var.cloudflare_logpush_dataset
  frequency = "low"
  filter = ""
  ownership_challenge = ""
  kind = ""
  lifecycle {
  }
}

resource "cloudflare_logpush_job" "crx-logpush-account" {
  count = local.dataset_type[var.cloudflare_logpush_dataset] == "account" ? 1 : 0 
  enabled             = true
  account_id = var.cloudflare_account_id
  name                = local.job_name
  logpull_options     = "fields=${coalesce(var.cloudflare_logpush_fields,local.dataset_full_fields[var.cloudflare_logpush_dataset])},${local.dataset_timestamp[var.cloudflare_logpush_dataset]}&timestamps=unixnano"
  destination_conf = var.coralogix_subsystem_name != "" || var.coralogix_application_name != "" ? "https://${local.coralogix_regions[var.coralogix_region]}/api/v1/cloudflare/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_CX-Application-Name=${var.coralogix_application_name}&header_CX-Subsystem-Name=${var.coralogix_subsystem_name}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}" : "https://${local.coralogix_regions[var.coralogix_region]}/api/v1/cloudflare/logs?header_Authorization=Bearer%20${var.coralogix_private_key}&header_timestamp-format=UnixNano&header_dataset=${local.coralogix_dataset[var.cloudflare_logpush_dataset]}&tags=dataset:${var.cloudflare_logpush_dataset}"
  dataset             = var.cloudflare_logpush_dataset
  frequency = "low"
  filter = ""
  ownership_challenge = ""
  kind = ""
  lifecycle {
  }
}
