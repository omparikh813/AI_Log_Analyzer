# PCAP Threat Analyzer

A PCAP-based network threat analysis engine for cybersecurity education. Point it at a packet capture and it produces HTML and JSON reports with severity-ranked findings, MITRE ATT&CK mappings, evidence, and remediation steps.

## Quick Start

```bash
pip install -r requirements.txt
python -m app.main sample_pcaps/capture.pcap
# Reports written to reports/
```

## What It Detects

| Category | Examples |
|---|---|
| Signature | Port scans, SYN floods, SMB exploitation, suspicious ports |
| Statistical | Beaconing, traffic spikes, packet size anomalies, rare protocols |
| Protocol | Weak TLS, SMBv1, FTP/Telnet cleartext auth, HTTP credential leaks, DNS tunneling |
| Correlation | Lateral movement, C2 communication, active reconnaissance, DNS exfiltration |

## Configuration

Key thresholds in `.env`:

| Variable | Default | Description |
|---|---|---|
| `PORT_SCAN_THRESHOLD` | `20` | Unique ports to trigger scan alert |
| `SYN_FLOOD_THRESHOLD` | `100` | SYN packets to trigger flood alert |
| `BEACON_INTERVAL_TOLERANCE` | `0.1` | Regularity threshold for beaconing |
| `TRAFFIC_SPIKE_MULTIPLIER` | `3.0` | Multiplier above baseline to flag as spike |
| `ENABLE_TLS_ANALYSIS` | `true` | Weak TLS detection |
| `ENABLE_DNS_ANALYSIS` | `true` | DNS tunneling detection |

## Tests

```bash
pytest tests/ -v
```
