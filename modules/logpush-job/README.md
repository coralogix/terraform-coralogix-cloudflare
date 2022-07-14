# logpush-job

Manage the cloudflare logpush job that sends specific logs to your *Coralogix* account.

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.20.0 |
| <a name="requirement_cloudflare"></a> [cloudflare](#requirement\_cloudflare) | >= 3.0.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_cloudflare"></a> [cloudflare](#provider\_cloudflare) | >= 3.19.0 |
| <a name="provider_random"></a> [random](#provider\_random) | >= 3.3.2 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_coralogix_region"></a> [coralogix\_region](#input\_coralogix\_region) | The Coralogix location region, possible options are [`Europe`, `Europe2`, `India`, `Singapore`, `US`] | `string` | `Europe` | no |
| <a name="input_coralogix_private_key"></a> [coralogix\_private\_key](#input\_coralogix\_private\_key) | The Coralogix private key which is used to validate your authenticity | `string` | n/a | yes |
| <a name="input_cloudflare_email"></a> [cloudflare\_email](#input\_cloudflare\_email) | The cloudflare email for authentication | `string` | n/a | yes |
| <a name="input_cloudflare_api_key"></a> [cloudflare\_api\_key](#input\_cloudflare\_api\_key) | The cloudflare api key for authentication | `string` | n/a | yes |
| <a name="input_cloudflare_logpush_dataset"></a> [cloudflare\_logpush\_dataset](#input\_cloudflare\_logpush\_dataset) | The cloudflare logpush job data-set | `string` | n/a | yes |
| <a name="input_cloudflare_logpush_fields"></a> [cloudflare\_logpush\_fields](#input\_cloudflare\_logpush\_fields) | The logpush dataset specific fields to log delimited with comma, leave empty to include all fields. the timestamp and its variants are included automatically. | `string` | "" | no |
| <a name="input_cloudflare_zone_id"></a> [cloudflare\_zone\_id](#input\_cloudflare\_zone\_id) | The cloudflare zone id for zone based data-sets | `string` | "" | yes (for zone-scoped datasets) |
| <a name="input_cloudflare_account_id"></a> [cloudflare\_account\_id](#input\_cloudflare\_account\_id) | The cloudflare account id for account based data-sets | `string` | "" | yes (for account-scoped datasets) |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_logpush_job_name"></a> [logpush\job\_name](#output\_logpush\_job\_name) | The name of the logpush job |
| <a name="output_logpush_job_scope"></a> [logpush\job\scope](#output\_logpush\_job\_scope) | The scope of the logpush job |

## Common errors

| Error | Description |
|------|-------------|
| creating a new job is not allowed: Bot Management fields are not allowed (1004) | Your cloudflare account plan doesnt allow the specified fields in cloudflare_logpush_fields|
| creating a new job is not allowed: exceeded max jobs allowed (1004) | Your cloudflare account plan doesnt allow the specified dataset in cloudflare_logpush_dataset|

## Values table

| Dataset | Scope | Fields |
|---------|-------|--------|
| dns_logs | zone | ColoCode, EDNSSubnet, EDNSSubnetLength, QueryName, QueryType, ResponseCached, ResponseCode, SourceIP
| firewall_events | zone | Action, ClientASN, ClientASNDescription, ClientCountry, ClientIP, ClientIPClass, ClientRefererHost, ClientRefererPath, ClientRefererQuery, ClientRefererScheme, ClientRequestHost,  ClientRequestMethod, ClientRequestPath, ClientRequestProtocol, ClientRequestQuery, ClientRequestScheme, ClientRequestUserAgent, EdgeColoCode, EdgeResponseStatus, Kind, MatchIndex, Metadata, OriginResponseStatus, OriginatorRayID, RayID, RuleID, Source
| http_requests | zone | BotScoreCloudflare, BotScoreSrc, BotTags, CacheCacheStatus, CacheResponseBytes, CacheResponseStatus, CacheTieredFill, ClientASN, ClientCountry, ClientDeviceType, ClientIP, ClientIPClass, ClientMTLSAuthCertFingerprint, ClientMTLSAuthStatus, ClientRequestBytes, ClientRequestHost, ClientRequestMethod, ClientRequestPath, ClientRequestProtocol, ClientRequestReferer, ClientRequestScheme, ClientRequestSource, ClientRequestURI, ClientRequestUserAgent, ClientSSLCipher, ClientSSLProtocol, ClientSrcPort, ClientTCPRTTMs, ClientXRequestedWith, EdgeCFConnectingO2O, EdgeColoCode, EdgeColoID, EdgeEndTimestamp, EdgePathingOp, EdgePathingSrc, EdgePathingStatus, EdgeRateLimitAction, EdgeRateLimitID, EdgeRequestHost, EdgeResponseBodyBytes, EdgeResponseBytes, EdgeResponseCompressionRatio, EdgeResponseContentType, EdgeResponseStatus, EdgeServerIP, EdgeTimeToFirstByteMs, FirewallMatchesActions, FirewallMatchesRuleIDs, FirewallMatchesSources, JA3Hash, OriginDNSResponseTimeMs, OriginIP, OriginRequestHeaderSendDurationMs, OriginResponseBytes, OriginResponseDurationMs, OriginResponseHTTPExpires, OriginResponseHTTPLastModified, OriginResponseHeaderReceiveDurationMs, OriginResponseStatus, OriginResponseTime, OriginSSLProtocol, OriginTCPHandshakeDurationMs, OriginTLSHandshakeDurationMs, ParentRayID, RayID, RequestHeaders, ResponseHeaders, SecurityLevel, SmartRouteColoID, UpperTierColoID, WAFAction, WAFFlags, WAFMatchedVar, WAFProfile, WAFRuleID, WAFRuleMessage, WorkerCPUTime, WorkerStatus, WorkerSubrequest, WorkerSubrequestCount, ZoneID, ZoneName
| nel_reports | zone | ClientIPASN, ClientIPASNDescription, ClientIPCountry, LastKnownGoodColoCode, Phase, Type
| spectrum_events | zone | Application, ClientAsn, ClientBytes, ClientCountry, ClientIP, ClientMatchedIpFirewall, ClientPort, ClientProto, ClientTcpRtt, ClientTlsCipher, ClientTlsClientHelloServerName, ClientTlsProtocol, ClientTlsStatus, ColoCode, ConnectTimestamp, DisconnectTimestamp, Event, IpFirewall, OriginBytes, OriginIP, OriginPort, OriginProto, OriginTcpRtt, OriginTlsCipher, OriginTlsFingerprint, OriginTlsMode, OriginTlsProtocol, OriginTlsStatus, ProxyProtocol, Status
| audit_logs | account | ActionResult, ActionType, ActorEmail, ActorID, ActorIP, ActorType, ID, Interface, Metadata, NewValue, OldValue, OwnerID, ResourceID, ResourceType
| gateway_dns | account | ColoID, ColoName, DeviceID, DstIP, DstPort, Email, Location, MatchedCategoryIDs, Policy, PolicyID, Protocol, QueryCategoryIDs, QueryName, QueryNameReversed, QuerySize, QueryType, RData, ResolverDecision, SrcIP, SrcPort, UserID
| gateway_http | account | AccountID, Action, BlockedFileHash, BlockedFileName, BlockedFileReason, BlockedFileSize, BlockedFileType, DestinationIP, DestinationPort, DeviceID, DownloadedFileNames, Email, HTTPHost, HTTPMethod, HTTPVersion,IsIsolated, PolicyID, Referer, RequestID, SourceIP, SourcePort, URL, UploadedFileNames, UserAgent, UserID
| gateway_network | account | AccountID, Action, DestinationIP, DestinationPort, DeviceID, Email, OverrideIP, OverridePort	, PolicyID, SNI, SessionID, SourceIP, SourcePort, Transport, UserID
| network_analytics_logs | account | AttackCampaignID, AttackID, ColoCountry, ColoGeoHash, ColoID, ColoName, DestinationASN, DestinationASNDescription, DestinationCountry, DestinationGeoHash, DestinationPort, Direction, GREChecksum, GREEthertype, GREHeaderLength, GREKey, GRESequenceNumber, GREVersion, ICMPChecksum, ICMPCode, ICMPType, IPDestinationAddress, IPDestinationSubnet, IPFragmentOffset, IPHeaderLength, IPMoreFragments, IPProtocol, IPProtocolName, IPSourceAddress, IPSourceSubnet, IPTotalLength, IPTotalLengthBuckets, IPTtl, IPTtlBuckets, IPv4Checksum, IPv4DontFragment, IPv4Dscp, IPv4Ecn, IPv4Identification, IPv4Options, IPv6Dscp, IPv6Ecn, IPv6ExtensionHeaders, IPv6FlowLabel, IPv6Identification, MitigationReason, MitigationScope, MitigationSystem, ProtocolState, RuleID, RulesetID, RulesetOverrideID, SampleInterval, SourceASN, SourceASNDescription, SourceCountry, SourceGeoHash, SourcePort, TCPAcknowledgementNumber, TCPChecksum, TCPDataOffset, TCPFlags, TCPFlagsString, TCPMss, TCPOptions, TCPSackBlocks, TCPSacksPermitted, TCPSequenceNumber, TCPTimestampEcr, TCPTimestampValue, TCPUrgentPointer, TCPWindowScale, TCPWindowSize, UDPChecksum, UDPPayloadLength, Verdict 