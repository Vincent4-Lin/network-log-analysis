# Network Log Analysis

This project analyzes synthetic network security logs and generates a basic incident-style report.

It is designed as a beginner-friendly cybersecurity portfolio project for graduate school applications, especially for network security, security operations, and threat analysis.

## Portfolio Position

This repository is an early focused project for firewall-style network log analysis. It is separate from [packet-analyzer](https://github.com/Vincent4-Lin/packet-analyzer), which works at the packet/pcap level, and narrower than [ai-soc-analyst](https://github.com/Vincent4-Lin/ai-soc-analyst), which combines multiple artifact types into a broader SOC triage workflow.

In the portfolio story, this project shows the first step: using transparent Python rules to turn simple network events into a security report.

## Purpose

The goal is to show practical understanding of:

- Network traffic patterns
- Suspicious connection behavior
- Port scanning indicators
- Repeated denied connections
- Suspicious outbound traffic
- Basic SOC-style reporting

## Why This Project

My background includes CCNA and I am preparing for CompTIA Security+. This project connects networking knowledge with cybersecurity analysis by using Python to review firewall-style logs and identify suspicious events.

## Project Structure

```text
network-log-analysis/
├── data/
│   └── network_events.csv
├── reports/
│   ├── analysis_report.md
│   └── suspicious_events.csv
├── src/
│   └── analyze_network_logs.py
├── .gitignore
└── README.md
```

## Detection Logic

The analyzer flags:

- Possible port scans
- Repeated denied connections
- High-volume outbound transfers
- Failed SSH login activity
- Traffic to risky or uncommon ports

The dataset is synthetic and created for learning purposes. It does not contain real user data or production logs.

## How to Run

```bash
python3 src/analyze_network_logs.py
```

The script reads:

```text
data/network_events.csv
```

and writes:

```text
reports/analysis_report.md
reports/suspicious_events.csv
```

## Example Output

The report includes:

- Total event count
- Allowed vs denied traffic summary
- Top source IPs
- Top destination ports
- Suspicious event findings
- Recommended mitigations

## Skills Demonstrated

- Python scripting
- CSV parsing
- Network security analysis
- Basic detection engineering
- Incident report writing
- GitHub portfolio documentation

## Next Improvements

- Add time-window based detection
- Add severity scoring
- Add JSON log support
- Add simple visualizations
- Compare internal vs external IP behavior
