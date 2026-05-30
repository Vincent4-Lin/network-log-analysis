# Network Log Analysis Report

## Executive Summary

- Total events analyzed: 22
- Suspicious findings: 6
- High severity findings: 4
- Medium severity findings: 2

## Traffic Summary

- Total outbound bytes: 15647790
- Total inbound bytes: 350680

### Action Counts

| Action | Count |
| --- | --- |
| ALLOW | 10 |
| DENY | 12 |

### Top Source IPs

| Source IP | Events |
| --- | --- |
| 203.0.113.44 | 6 |
| 198.51.100.88 | 4 |
| 10.0.1.40 | 2 |
| 10.0.1.25 | 2 |
| 10.0.1.15 | 1 |

### Top Destination Ports

| Destination Port | Events |
| --- | --- |
| 443 | 7 |
| 22 | 5 |
| 53 | 2 |
| 23 | 1 |
| 80 | 1 |

### Event Type Counts

| Event Type | Count |
| --- | --- |
| web_browsing | 4 |
| blocked_connection | 8 |
| unusual_port | 2 |
| outbound_transfer | 2 |
| failed_ssh | 4 |
| dns_query | 2 |

## Suspicious Findings

| Severity | Finding | Source | Destination | Port | Reason |
| --- | --- | --- | --- | --- | --- |
| medium | Allowed traffic to risky or uncommon port | 10.0.1.33 | 198.51.100.20 | 4444 | Destination port 4444 is associated with Common reverse shell port |
| high | High-volume outbound transfer | 10.0.1.40 | 192.0.2.77 | 443 | bytes_out is 8210340, above threshold 5000000 |
| high | High-volume outbound transfer | 10.0.1.40 | 192.0.2.77 | 443 | bytes_out is 7428120, above threshold 5000000 |
| medium | Allowed traffic to risky or uncommon port | 10.0.1.50 | 203.0.113.55 | 5900 | Destination port 5900 is associated with VNC |
| high | Possible port scan | 203.0.113.44 | 10.0.1.10 | 22,23,80,443,3389,8080 | 203.0.113.44 attempted 6 unique destination ports on 10.0.1.10 |
| high | Repeated failed SSH attempts | 198.51.100.88 | 10.0.1.22 | 22 | 4 failed SSH attempts from 198.51.100.88 to 10.0.1.22 |

## Recommended Mitigations

- Review firewall rules for allowed traffic to uncommon ports.
- Investigate high-volume outbound transfers from internal hosts.
- Block or rate-limit repeated failed SSH attempts.
- Confirm whether exposed services such as SSH, RDP, SMB, or VNC are required.
- Add monitoring for port scan patterns and repeated denied connections.

## Notes

This report is based on synthetic data for portfolio and learning purposes.
