import statistics
from collections import defaultdict
from typing import Dict, List, Tuple

from app.models import Confidence, Finding, Flow, MitreAttack, PacketInfo, Severity
from app.utils import generate_id, setup_logging

logger = setup_logging(__name__)


def run_signature_detection(packets: List[PacketInfo], flows: List[Flow]) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_detect_port_scans(packets))
    findings.extend(_detect_syn_flood(packets))
    findings.extend(_detect_smb_exploitation(packets))
    findings.extend(_detect_suspicious_ports(packets))
    return findings


def run_statistical_detection(packets: List[PacketInfo], flows: List[Flow]) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_detect_packet_size_anomalies(packets))
    findings.extend(_detect_traffic_spikes(packets))
    findings.extend(_detect_rare_protocols(packets))
    findings.extend(_detect_beaconing(flows))
    return findings


# ─── Signature Detection ──────────────────────────────────────────────────────

def _detect_port_scans(packets: List[PacketInfo]) -> List[Finding]:
    from config import PORT_SCAN_THRESHOLD

    findings: List[Finding] = []
    syn_targets: Dict[str, set] = defaultdict(set)

    for pkt in packets:
        if pkt.protocol == "TCP" and pkt.flags and "S" in pkt.flags and "A" not in pkt.flags:
            syn_targets[pkt.src_ip].add((pkt.dst_ip, pkt.dst_port))

    for src_ip, targets in syn_targets.items():
        unique_ports = {port for _, port in targets}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            findings.append(Finding(
                finding_id=generate_id("SIG"),
                title="Port Scan Detected",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                mitre_attacks=[MitreAttack("T1046", "Network Service Discovery")],
                description=(
                    f"Host {src_ip} sent SYN packets to {len(unique_ports)} unique ports, "
                    "indicating an active port scan against the network."
                ),
                evidence=[
                    f"Source IP: {src_ip}",
                    f"Unique destination ports probed: {len(unique_ports)}",
                    f"Sample ports: {sorted(unique_ports)[:10]}",
                ],
                remediation=[
                    "Block the scanning source IP at the perimeter firewall.",
                    "Review IDS/IPS rules for port scan detection signatures.",
                    "Monitor for follow-up exploitation attempts from this IP.",
                ],
                timestamp=min(p.timestamp for p in packets if p.src_ip == src_ip),
                source_ips=[src_ip],
                category="Signature",
            ))
    return findings


def _detect_syn_flood(packets: List[PacketInfo]) -> List[Finding]:
    from config import SYN_FLOOD_THRESHOLD

    findings: List[Finding] = []
    syn_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for pkt in packets:
        if pkt.protocol == "TCP" and pkt.flags and "S" in pkt.flags and "A" not in pkt.flags:
            syn_counts[pkt.dst_ip][pkt.src_ip] += 1

    for dst_ip, sources in syn_counts.items():
        total_syns = sum(sources.values())
        if total_syns >= SYN_FLOOD_THRESHOLD:
            top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5]
            findings.append(Finding(
                finding_id=generate_id("SIG"),
                title="SYN Flood Attack Detected",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                mitre_attacks=[MitreAttack("T1498", "Network Denial of Service")],
                description=(
                    f"Target {dst_ip} received {total_syns} SYN packets from "
                    f"{len(sources)} unique sources, consistent with a SYN flood DoS attack."
                ),
                evidence=[
                    f"Destination IP: {dst_ip}",
                    f"Total SYN packets: {total_syns}",
                    f"Unique source IPs: {len(sources)}",
                    f"Top sources by volume: {top_sources}",
                ],
                remediation=[
                    "Enable SYN cookies on the affected host.",
                    "Rate-limit inbound SYN packets at the perimeter firewall.",
                    "Contact upstream ISP for traffic scrubbing if volumetric.",
                ],
                timestamp=min(p.timestamp for p in packets if p.dst_ip == dst_ip),
                destination_ips=[dst_ip],
                category="Signature",
            ))
    return findings


def _detect_smb_exploitation(packets: List[PacketInfo]) -> List[Finding]:
    findings: List[Finding] = []
    smb_ports = {445, 139}
    smb_targets: Dict[str, set] = defaultdict(set)

    for pkt in packets:
        if pkt.dst_port in smb_ports:
            smb_targets[pkt.src_ip].add(pkt.dst_ip)

    for src_ip, targets in smb_targets.items():
        if len(targets) > 5:
            findings.append(Finding(
                finding_id=generate_id("SIG"),
                title="SMB Exploitation Indicators Detected",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                mitre_attacks=[
                    MitreAttack("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
                    MitreAttack("T1046", "Network Service Discovery"),
                ],
                description=(
                    f"Host {src_ip} made SMB connections to {len(targets)} unique targets, "
                    "suggesting lateral movement or exploitation via SMB."
                ),
                evidence=[
                    f"Source IP: {src_ip}",
                    f"Unique SMB targets: {len(targets)}",
                    f"Sample targets: {list(targets)[:5]}",
                ],
                remediation=[
                    "Isolate the source host from the network immediately.",
                    "Disable SMBv1 and audit exposed SMB shares.",
                    "Review authentication logs on all targeted hosts.",
                    "Verify MS17-010 (EternalBlue) patches are applied.",
                ],
                timestamp=min(p.timestamp for p in packets if p.src_ip == src_ip),
                source_ips=[src_ip],
                category="Signature",
            ))
    return findings


def _detect_suspicious_ports(packets: List[PacketInfo]) -> List[Finding]:
    from config import SUSPICIOUS_PORTS

    findings: List[Finding] = []
    port_contacts: Dict[int, set] = defaultdict(set)

    for pkt in packets:
        if pkt.dst_port in SUSPICIOUS_PORTS:
            port_contacts[pkt.dst_port].add(pkt.src_ip)

    for port, sources in port_contacts.items():
        findings.append(Finding(
            finding_id=generate_id("SIG"),
            title=f"Suspicious Port Activity (Port {port})",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            mitre_attacks=[MitreAttack("T1571", "Non-Standard Port")],
            description=(
                f"Traffic detected on port {port}, commonly associated with backdoors, "
                "remote access trojans (RATs), or malicious C2 frameworks."
            ),
            evidence=[
                f"Suspicious destination port: {port}",
                f"Source IPs observed: {list(sources)[:5]}",
            ],
            remediation=[
                f"Block port {port} at the perimeter unless explicitly authorized.",
                "Investigate any process listening on or connecting to this port.",
                "Capture the full session payload for deeper analysis.",
            ],
            timestamp=min(p.timestamp for p in packets if p.dst_port == port),
            source_ips=list(sources),
            category="Signature",
        ))
    return findings


# ─── Statistical Detection ────────────────────────────────────────────────────

def _detect_packet_size_anomalies(packets: List[PacketInfo]) -> List[Finding]:
    if len(packets) < 10:
        return []

    sizes = [p.size for p in packets]
    mean = statistics.mean(sizes)
    stdev = statistics.stdev(sizes) if len(sizes) > 1 else 0

    if stdev == 0:
        return []

    anomalous = [p for p in packets if abs(p.size - mean) > 3 * stdev]
    if not anomalous:
        return []

    return [Finding(
        finding_id=generate_id("STAT"),
        title="Packet Size Anomaly Detected",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        mitre_attacks=[MitreAttack("T1030", "Data Transfer Size Limits")],
        description=(
            f"Detected {len(anomalous)} packets with sizes deviating more than 3 standard "
            f"deviations from the mean ({mean:.0f} bytes, σ={stdev:.0f} bytes). "
            "Unusually large packets may indicate data exfiltration."
        ),
        evidence=[
            f"Mean packet size: {mean:.0f} bytes",
            f"Standard deviation: {stdev:.0f} bytes",
            f"Anomalous packet count: {len(anomalous)}",
            f"Sample anomalous sizes (bytes): {[p.size for p in anomalous[:5]]}",
        ],
        remediation=[
            "Inspect large packets for data exfiltration content.",
            "Review DLP policies for oversized outbound transfers.",
        ],
        timestamp=anomalous[0].timestamp,
        category="Statistical",
    )]


def _detect_traffic_spikes(packets: List[PacketInfo]) -> List[Finding]:
    from config import TRAFFIC_SPIKE_MULTIPLIER

    if len(packets) < 20:
        return []

    interval_counts: Dict[int, int] = defaultdict(int)
    for pkt in packets:
        interval_counts[int(pkt.timestamp)] += 1

    if len(interval_counts) < 3:
        return []

    counts = list(interval_counts.values())
    mean = statistics.mean(counts)
    spike_intervals = {
        ts: count for ts, count in interval_counts.items()
        if count > mean * TRAFFIC_SPIKE_MULTIPLIER
    }

    if not spike_intervals:
        return []

    return [Finding(
        finding_id=generate_id("STAT"),
        title="Traffic Volume Spike Detected",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        mitre_attacks=[MitreAttack("T1498", "Network Denial of Service")],
        description=(
            f"Traffic volume exceeded {TRAFFIC_SPIKE_MULTIPLIER}x the baseline average "
            f"({mean:.0f} pps) during {len(spike_intervals)} one-second intervals, "
            "consistent with a burst attack or exfiltration event."
        ),
        evidence=[
            f"Baseline average: {mean:.0f} packets/second",
            f"Spike threshold: {mean * TRAFFIC_SPIKE_MULTIPLIER:.0f} packets/second",
            f"Spike intervals detected: {len(spike_intervals)}",
            f"Peak observed: {max(spike_intervals.values())} pps",
        ],
        remediation=[
            "Investigate the traffic source during identified spike windows.",
            "Review rate-limiting and DDoS mitigation configuration.",
        ],
        timestamp=float(min(spike_intervals.keys())),
        category="Statistical",
    )]


def _detect_rare_protocols(packets: List[PacketInfo]) -> List[Finding]:
    findings: List[Finding] = []
    proto_counts: Dict[str, int] = defaultdict(int)
    for pkt in packets:
        proto_counts[pkt.protocol] += 1

    total = len(packets)
    if total == 0:
        return []

    common = {"TCP", "UDP", "ICMP"}
    for proto, count in proto_counts.items():
        if proto in common:
            continue
        if count / total < 0.01:
            findings.append(Finding(
                finding_id=generate_id("STAT"),
                title=f"Rare Protocol Usage: {proto}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                mitre_attacks=[MitreAttack("T1095", "Non-Application Layer Protocol")],
                description=(
                    f"Protocol {proto} accounts for only {count}/{total} packets (<1%). "
                    "Uncommon protocols may indicate covert tunneling or network misconfiguration."
                ),
                evidence=[
                    f"Protocol: {proto}",
                    f"Packet count: {count}",
                    f"Percentage of traffic: {count / total * 100:.2f}%",
                ],
                remediation=[
                    f"Verify that {proto} traffic is expected in this environment.",
                    f"Block {proto} at the perimeter if not required.",
                ],
                timestamp=next(p.timestamp for p in packets if p.protocol == proto),
                category="Statistical",
            ))
    return findings


def _detect_beaconing(flows: List[Flow]) -> List[Finding]:
    from config import BEACON_INTERVAL_TOLERANCE

    findings: List[Finding] = []
    connection_times: Dict[Tuple[str, str], List[float]] = defaultdict(list)

    for flow in flows:
        connection_times[(flow.src_ip, flow.dst_ip)].append(flow.start_time)

    for (src_ip, dst_ip), times in connection_times.items():
        if len(times) < 5:
            continue

        times_sorted = sorted(times)
        intervals = [times_sorted[i + 1] - times_sorted[i] for i in range(len(times_sorted) - 1)]
        if not intervals:
            continue

        mean_interval = statistics.mean(intervals)
        if mean_interval < 1:
            continue

        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = stdev_interval / mean_interval if mean_interval > 0 else 1.0

        if cv <= BEACON_INTERVAL_TOLERANCE:
            findings.append(Finding(
                finding_id=generate_id("STAT"),
                title="Beaconing Behavior Detected",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                mitre_attacks=[
                    MitreAttack("T1071", "Application Layer Protocol"),
                    MitreAttack("T1008", "Fallback Channels"),
                ],
                description=(
                    f"Host {src_ip} is making highly regular connections to {dst_ip} "
                    f"approximately every {mean_interval:.1f} seconds (CV={cv:.3f}). "
                    "This regularity is consistent with automated malware beaconing to a C2 server."
                ),
                evidence=[
                    f"Source IP: {src_ip}",
                    f"Destination IP: {dst_ip}",
                    f"Connection count: {len(times)}",
                    f"Mean beacon interval: {mean_interval:.2f} seconds",
                    f"Coefficient of variation: {cv:.3f} (low = very regular)",
                ],
                remediation=[
                    f"Block all traffic from {src_ip} to {dst_ip} at the firewall.",
                    "Conduct full malware investigation on the source host.",
                    "Capture full session payload for C2 protocol analysis.",
                    "Query threat intelligence feeds for the destination IP.",
                ],
                timestamp=times_sorted[0],
                source_ips=[src_ip],
                destination_ips=[dst_ip],
                category="Statistical",
            ))
    return findings
