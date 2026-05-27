# PCAP Threat Analyzer

A production-style PCAP-based network threat analysis engine for cybersecurity education. Parses packet captures and applies signature detection, statistical anomaly detection, protocol analysis, and threat correlation to surface actionable findings with MITRE ATT&CK mappings.

## Features

- **PCAP parsing** — extracts packet metadata and reconstructs TCP/UDP flows
- **Signature detection** — port scans, SYN floods, SMB exploitation, suspicious ports
- **Statistical detection** — packet size anomalies, traffic spikes, rare protocols, beaconing
- **Protocol analysis** — weak TLS versions, SMBv1, FTP/Telnet cleartext auth, HTTP credential leaks
- **Threat correlation** — combines related findings into high-level threat scenarios
- **Reporting** — HTML and JSON reports with severity, confidence, MITRE ATT&CK, evidence, and remediation

## Project Structure

```
pcap-threat-analyzer/
├── app/
│   ├── main.py          # Entry point and orchestration
│   ├── parser.py        # PCAP parsing and flow reconstruction
│   ├── detector.py      # Signature and statistical detection
│   ├── analyzer.py      # Protocol analysis
│   ├── correlation.py   # Threat correlation engine
│   ├── reporting.py     # HTML and JSON report generation
│   ├── models.py        # Data models
│   └── utils.py         # Shared utilities
├── tests/
│   └── test_detection.py
├── sample_pcaps/        # Place PCAP files here
├── reports/             # Generated reports land here
├── config.py            # Configuration loader
├── .env                 # Environment variables
└── requirements.txt
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m app.main sample_pcaps/capture.pcap
```

Reports are written to `reports/` as both HTML and JSON.

## Configuration

Edit `.env` to tune detection thresholds:

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `MAX_PCAP_SIZE_GB` | `5` | Maximum PCAP file size |
| `REPORT_OUTPUT_DIR` | `reports/` | Output directory |
| `ENABLE_TLS_ANALYSIS` | `true` | Enable weak TLS detection |
| `ENABLE_DNS_ANALYSIS` | `true` | Enable DNS tunneling detection |
| `PORT_SCAN_THRESHOLD` | `20` | Unique ports to trigger scan alert |
| `SYN_FLOOD_THRESHOLD` | `100` | SYN packets to trigger flood alert |
| `BEACON_INTERVAL_TOLERANCE` | `0.1` | CV threshold for beaconing (lower = stricter) |
| `TRAFFIC_SPIKE_MULTIPLIER` | `3.0` | Multiplier above baseline to flag as spike |

## Running Tests

```bash
pytest tests/ -v
```

## Detection Capabilities

### Signature-Based
| Detection | Severity | MITRE ATT&CK |
|---|---|---|
| Port scan | MEDIUM | T1046 |
| SYN flood | HIGH | T1498 |
| SMB exploitation indicators | HIGH | T1021.002 |
| Suspicious ports (RAT/backdoor) | MEDIUM | T1571 |

### Statistical
| Detection | Severity | MITRE ATT&CK |
|---|---|---|
| Packet size anomalies | LOW | T1030 |
| Traffic volume spikes | MEDIUM | T1498 |
| Rare protocol usage | LOW | T1095 |
| Beaconing behavior | HIGH | T1071 |

### Protocol Analysis
| Detection | Severity | MITRE ATT&CK |
|---|---|---|
| Weak TLS (SSLv3/TLS 1.0/1.1) | MEDIUM | T1040 |
| SMBv1 usage | HIGH | T1210 |
| FTP cleartext authentication | HIGH | T1552.001 |
| Telnet sessions | HIGH | T1557 |
| HTTP credential leaks | HIGH | T1552.001 |
| DNS tunneling | CRITICAL | T1071.004 |

### Threat Correlation
| Scenario | Severity |
|---|---|
| Lateral movement (scan + SMB) | HIGH |
| C2 communication (beaconing) | HIGH |
| Active reconnaissance (port scan) | MEDIUM |
| DNS data exfiltration | CRITICAL |

## Implementation Roadmap

- [x] Phase 1 — PCAP parser, flow reconstruction
- [x] Phase 2 — Detection engine (signature + statistical + protocol)
- [x] Phase 3 — Threat correlation, severity scoring, HTML/JSON reporting
- [ ] Phase 4 — Testing and optimization
