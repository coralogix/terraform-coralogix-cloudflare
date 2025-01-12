# logpush-job

Manage the cloudflare logpush job that sends specific logs to your *Coralogix* account.
WARNING: Breaking Change in version 1.10 - New output_options added in cloudflare/cloudflare
## Usage

```hcl
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  email   = "example@coralogix.com"
  api_key = "XXXXXXXXXX"
}

module "logpush-job" {
    source = "coralogix/cloudflare/coralogix//modules/logpush-job"

    coralogix_region   = "Europe"
    coralogix_private_key = "XXXXXX-XXXXX"
    coralogix_application_name = "myapp_cloudflare"
    coralogix_subsystem_name = "mysub_cloudflare"
    cloudflare_logpush_dataset = "http_requests"
    cloudflare_logpush_fields = ["EdgeStartTimestamp", "EdgePathingOp", "EdgePathingSrc"] # Need to include 'Timestamp' key, can be left empty aswell for all fields
    cloudflare_zone_id = "xxxxxxxxxxxxxxxxxxxxx" # to be used with zone-scoped datasets
    # cloudflare_account_id = "xxxxxxxxxxxxxxxx" # to be used with account-scoped datasets
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.20.0 |
| <a name="requirement_cloudflare"></a> [cloudflare](#requirement\_cloudflare) | >= 4.0.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_cloudflare"></a> [cloudflare](#provider\_cloudflare) | >= 4.38.0 |
| <a name="provider_random"></a> [random](#provider\_random) | >= 3.3.2 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_coralogix_region"></a> [coralogix\_region](#input\_coralogix\_region) | The Coralogix location region, possible options are [`EU1`, `EU2`, `AP1`, `AP2`, `US1`, `US2`, `AP3`] | `string` | `EU1` | no |
| <a name="input_coralogix_private_key"></a> [coralogix\_private\_key](#input\_coralogix\_private\_key) | The Coralogix private key which is used to validate your authenticity | `string` | n/a | yes |
| <a name="input_coralogix_application_name"></a> [coralogix\_application\_name](#input\_coralogix\_application\_name) | The Coralogix Application Name for your logs | `string` | `cx-Cloudflare-Logpush-default-application` | no |
| <a name="input_coralogix_subsystem_name"></a> [coralogix\_subsystem\_name](#input\_coralogix\_subsystem\_name) | The Coralogix SubSystem Name for your logs | `string` | `cx-Cloudflare-Logpush-default-subsystem` | no |
| <a name="input_cloudflare_logpush_dataset"></a> [cloudflare\_logpush\_dataset](#input\_cloudflare\_logpush\_dataset) | The cloudflare logpush job data-set | `string` | n/a | yes |
| <a name="input_cloudflare_logpush_fields"></a> [cloudflare\_logpush\_fields](#input\_cloudflare\_logpush\_fields) | The logpush dataset specific fields to log delimited with comma, leave empty to include all fields. the timestamp and its variants are included automatically. | `string` | "" | no |
| <a name="input_cloudflare_zone_id"></a> [cloudflare\_zone\_id](#input\_cloudflare\_zone\_id) | The cloudflare zone id for zone based data-sets | `string` | "" | yes (for zone-scoped datasets) |
| <a name="input_cloudflare_account_id"></a> [cloudflare\_account\_id](#input\_cloudflare\_account\_id) | The cloudflare account id for account based data-sets | `string` | "" | yes (for account-scoped datasets) |
| <a name="input_max_upload_interval_seconds"></a> [max\_upload\_interval\_seconds](#input\_max\_upload\_interval\_seconds) | The maximum interval in seconds for log batches. This setting must be between 30 and 300 seconds (5 minutes). This parameter is not available for jobs with `edge` as its kind. | `number` | n/a | no |


## Outputs

| Name | Description |
|------|-------------|
| <a name="output_logpush_job_name"></a> [logpush\_job\_name](#output\_logpush\_job\_name) | The name of the logpush job |
| <a name="output_logpush_job_scope"></a> [logpush\_job\_scope](#output\_logpush\_job\_scope) | The scope of the logpush job |

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