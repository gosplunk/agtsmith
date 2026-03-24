# BOTSv3 Sourcetype Coverage

BOTSv3 is benchmark-only. It improves SPL structure and validation, but does not define production defaults.

Coverage modes:
- `specialized`: dedicated intent/template and planner guidance exists
- `generic_overview`: explicit sourcetype-preserving safe overview query is available

| Sourcetype | Coverage | Runtime Path |
|---|---|---|
| `access_combined` | `specialized` | `apache_access_top_ips / apache_suspicious_user_agents` |
| `alternatives` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `amazon-ssm-agent` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `amazon-ssm-agent-too_small` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `apache_error` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:cloudtrail` | `specialized` | `aws_cloudtrail_activity` |
| `aws:cloudwatch` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:cloudwatch:guardduty` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:cloudwatchlogs` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:cloudwatchlogs:vpcflow` | `specialized` | `aws_vpc_flow_activity` |
| `aws:config:rule` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:description` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:elb:accesslogs` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:rds:audit` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:rds:error` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `aws:s3:accesslogs` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `bandwidth` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `bash_history` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `bootstrap` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `cisco:asa` | `specialized` | `cisco_asa_network_flows` |
| `cloud-init` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `cloud-init-output` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `code42:api` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `code42:computer` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `code42:org` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `code42:security` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `code42:user` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `config_file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `cpu` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `cron-too_small` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `df` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `dmesg` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `dpkg` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `error-too_small` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `errors` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `errors-too_small` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `ess_content_importer` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `hardware` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `history-2` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `interfaces` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `iostat` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `lastlog` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `linux_audit` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `linux_secure` | `specialized` | `linux_privilege_escalation_activity` |
| `localhost-5` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `lsof` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `maillog-too_small` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `ms:aad:audit` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `ms:aad:signin` | `specialized` | `aad_signin_activity` |
| `ms:o365:management` | `specialized` | `o365_management_activity` |
| `ms:o365:reporting:messagetrace` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `netstat` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `o365:management:activity` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `openPorts` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `osquery:info` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `osquery:results` | `specialized` | `osquery_process_activity` |
| `osquery:warning` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `out-3` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `package` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `PerfmonMk:Process` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `protocol` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `ps` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Script:GetEndpointInfo` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Script:InstalledApps` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Script:ListeningPorts` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:arp` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:dhcp` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:dns` | `specialized` | `stream_dns_activity` |
| `stream:http` | `specialized` | `stream_http_activity` |
| `stream:icmp` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:igmp` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:ip` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:mysql` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:smb` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:smtp` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:tcp` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `stream:udp` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:agent:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:agt_system:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:behavior:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:packet:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:risk:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:scm_system:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:security:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `symantec:ep:traffic:file` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `syslog` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `time` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `top` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Unix:ListeningPorts` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Unix:Service` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Unix:SSHDConfig` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Unix:Update` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Unix:Uptime` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Unix:UserAccounts` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `Unix:Version` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `usersWithLoginPrivs` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `vmstat` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `who` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `WinEventLog` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `WinHostMon` | `generic_overview` | `botsv3_named_sourcetype_overview` |
| `xmlwineventlog` | `generic_overview` | `botsv3_named_sourcetype_overview` |

Generic overview shape:
```spl
search index=botsv3 sourcetype=<exact_sourcetype> | stats count by host source sourcetype | sort - count | head 20
```
