import csv
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = BASE_DIR / "data" / "network_events.csv"
REPORT_PATH = BASE_DIR / "reports" / "analysis_report.md"
SUSPICIOUS_EVENTS_PATH = BASE_DIR / "reports" / "suspicious_events.csv"

RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Common reverse shell port",
    5900: "VNC",
    8080: "Alternate HTTP",
}

HIGH_OUTBOUND_THRESHOLD = 5_000_000
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 5
FAILED_SSH_THRESHOLD = 3


def load_events(path):
    with path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        events = list(reader)

    for event in events:
        event["dst_port"] = int(event["dst_port"])
        event["bytes_out"] = int(event["bytes_out"])
        event["bytes_in"] = int(event["bytes_in"])

    return events


def is_internal_ip(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")


def detect_suspicious_events(events):
    findings = []
    denied_ports_by_source = defaultdict(set)
    failed_ssh_by_source = Counter()

    for event in events:
        src_ip = event["src_ip"]
        dst_ip = event["dst_ip"]
        dst_port = event["dst_port"]
        action = event["action"]
        event_type = event["event_type"]

        if action == "DENY":
            denied_ports_by_source[(src_ip, dst_ip)].add(dst_port)

        if event_type == "failed_ssh":
            failed_ssh_by_source[(src_ip, dst_ip)] += 1

        if event["bytes_out"] >= HIGH_OUTBOUND_THRESHOLD and is_internal_ip(src_ip):
            findings.append(
                {
                    **event,
                    "severity": "high",
                    "finding": "High-volume outbound transfer",
                    "reason": f"bytes_out is {event['bytes_out']}, above threshold {HIGH_OUTBOUND_THRESHOLD}",
                }
            )

        if dst_port in RISKY_PORTS and action == "ALLOW":
            findings.append(
                {
                    **event,
                    "severity": "medium",
                    "finding": "Allowed traffic to risky or uncommon port",
                    "reason": f"Destination port {dst_port} is associated with {RISKY_PORTS[dst_port]}",
                }
            )

    for (src_ip, dst_ip), ports in denied_ports_by_source.items():
        if len(ports) >= PORT_SCAN_UNIQUE_PORT_THRESHOLD:
            findings.append(
                {
                    "timestamp": "multiple",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": ",".join(str(port) for port in sorted(ports)),
                    "protocol": "TCP",
                    "action": "DENY",
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "event_type": "port_scan_pattern",
                    "severity": "high",
                    "finding": "Possible port scan",
                    "reason": f"{src_ip} attempted {len(ports)} unique destination ports on {dst_ip}",
                }
            )

    for (src_ip, dst_ip), count in failed_ssh_by_source.items():
        if count >= FAILED_SSH_THRESHOLD:
            findings.append(
                {
                    "timestamp": "multiple",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": 22,
                    "protocol": "TCP",
                    "action": "DENY",
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "event_type": "failed_ssh_burst",
                    "severity": "high",
                    "finding": "Repeated failed SSH attempts",
                    "reason": f"{count} failed SSH attempts from {src_ip} to {dst_ip}",
                }
            )

    return findings


def summarize(events):
    action_counts = Counter(event["action"] for event in events)
    event_type_counts = Counter(event["event_type"] for event in events)
    top_sources = Counter(event["src_ip"] for event in events).most_common(5)
    top_ports = Counter(event["dst_port"] for event in events).most_common(5)
    total_bytes_out = sum(event["bytes_out"] for event in events)
    total_bytes_in = sum(event["bytes_in"] for event in events)

    return {
        "action_counts": action_counts,
        "event_type_counts": event_type_counts,
        "top_sources": top_sources,
        "top_ports": top_ports,
        "total_bytes_out": total_bytes_out,
        "total_bytes_in": total_bytes_in,
    }


def write_suspicious_events(findings, path):
    fieldnames = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "action",
        "bytes_out",
        "bytes_in",
        "event_type",
        "severity",
        "finding",
        "reason",
    ]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)


def markdown_table(rows, headers):
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]

    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")

    return "\n".join(lines)


def write_report(events, summary, findings, path):
    severity_counts = Counter(finding["severity"] for finding in findings)

    report = [
        "# Network Log Analysis Report",
        "",
        "## Executive Summary",
        "",
        f"- Total events analyzed: {len(events)}",
        f"- Suspicious findings: {len(findings)}",
        f"- High severity findings: {severity_counts.get('high', 0)}",
        f"- Medium severity findings: {severity_counts.get('medium', 0)}",
        "",
        "## Traffic Summary",
        "",
        f"- Total outbound bytes: {summary['total_bytes_out']}",
        f"- Total inbound bytes: {summary['total_bytes_in']}",
        "",
        "### Action Counts",
        "",
        markdown_table(summary["action_counts"].items(), ["Action", "Count"]),
        "",
        "### Top Source IPs",
        "",
        markdown_table(summary["top_sources"], ["Source IP", "Events"]),
        "",
        "### Top Destination Ports",
        "",
        markdown_table(summary["top_ports"], ["Destination Port", "Events"]),
        "",
        "### Event Type Counts",
        "",
        markdown_table(summary["event_type_counts"].items(), ["Event Type", "Count"]),
        "",
        "## Suspicious Findings",
        "",
    ]

    if findings:
        finding_rows = [
            [
                finding["severity"],
                finding["finding"],
                finding["src_ip"],
                finding["dst_ip"],
                finding["dst_port"],
                finding["reason"],
            ]
            for finding in findings
        ]
        report.append(
            markdown_table(
                finding_rows,
                ["Severity", "Finding", "Source", "Destination", "Port", "Reason"],
            )
        )
    else:
        report.append("No suspicious events were identified.")

    report.extend(
        [
            "",
            "## Recommended Mitigations",
            "",
            "- Review firewall rules for allowed traffic to uncommon ports.",
            "- Investigate high-volume outbound transfers from internal hosts.",
            "- Block or rate-limit repeated failed SSH attempts.",
            "- Confirm whether exposed services such as SSH, RDP, SMB, or VNC are required.",
            "- Add monitoring for port scan patterns and repeated denied connections.",
            "",
            "## Notes",
            "",
            "This report is based on synthetic data for portfolio and learning purposes.",
        ]
    )

    path.write_text("\n".join(report) + "\n", encoding="utf-8")


def main():
    events = load_events(DATA_PATH)
    findings = detect_suspicious_events(events)
    summary = summarize(events)

    write_suspicious_events(findings, SUSPICIOUS_EVENTS_PATH)
    write_report(events, summary, findings, REPORT_PATH)

    print(f"Analyzed {len(events)} events")
    print(f"Suspicious findings: {len(findings)}")
    print(f"Report written to: {REPORT_PATH}")
    print(f"Suspicious events written to: {SUSPICIOUS_EVENTS_PATH}")


if __name__ == "__main__":
    main()
