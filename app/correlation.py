from typing import List

from app.models import Confidence, Finding, MitreAttack, Severity
from app.utils import generate_id, setup_logging

logger = setup_logging(__name__)


def correlate_threats(findings: List[Finding]) -> List[Finding]:
    """Combine individual findings into correlated threat scenarios."""
    correlated: List[Finding] = []
    correlated.extend(_correlate_lateral_movement(findings))
    correlated.extend(_correlate_c2_communication(findings))
    correlated.extend(_correlate_reconnaissance(findings))
    correlated.extend(_correlate_data_exfiltration(findings))
    return correlated


def _correlate_lateral_movement(findings: List[Finding]) -> List[Finding]:
    has_port_scan = any("Port Scan" in f.title for f in findings)
    has_smb = any("SMB" in f.title for f in findings)

    if not (has_port_scan and has_smb):
        return []

    scan = next(f for f in findings if "Port Scan" in f.title)
    smb = next(f for f in findings if "SMB" in f.title)
    combined_src = list(set(scan.source_ips + smb.source_ips))
    combined_dst = list(set(scan.destination_ips + smb.destination_ips))

    return [Finding(
        finding_id=generate_id("CORR"),
        title="Possible Lateral Movement Campaign",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        mitre_attacks=[
            MitreAttack("T1046", "Network Service Discovery"),
            MitreAttack("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
            MitreAttack("T1570", "Lateral Tool Transfer"),
        ],
        description=(
            "Correlation of active port scanning with subsequent SMB activity from overlapping "
            "source IPs indicates a possible lateral movement campaign. An attacker may be "
            "mapping the internal network and propagating via SMB exploitation."
        ),
        evidence=[
            "Port scan activity detected (see related finding)",
            "SMB exploitation indicators detected (see related finding)",
            f"Overlapping source IPs: {combined_src[:5]}",
        ],
        remediation=[
            "Isolate all identified source hosts from the network immediately.",
            "Review endpoint and domain controller logs for unauthorized changes.",
            "Audit Active Directory for privilege escalation or new accounts.",
            "Verify all authentication activity across the environment.",
        ],
        timestamp=min(scan.timestamp, smb.timestamp),
        source_ips=combined_src,
        destination_ips=combined_dst,
        category="Correlation",
    )]


def _correlate_c2_communication(findings: List[Finding]) -> List[Finding]:
    has_beaconing = any("Beaconing" in f.title for f in findings)
    if not has_beaconing:
        return []

    beacon = next(f for f in findings if "Beaconing" in f.title)

    return [Finding(
        finding_id=generate_id("CORR"),
        title="Possible Command & Control (C2) Communication",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        mitre_attacks=[
            MitreAttack("T1071", "Application Layer Protocol"),
            MitreAttack("T1105", "Ingress Tool Transfer"),
            MitreAttack("T1008", "Fallback Channels"),
        ],
        description=(
            "Regular beaconing behavior to an external destination is consistent with malware "
            "C2 communication. The highly consistent interval indicates automated, programmatic "
            "callbacks rather than human-driven traffic."
        ),
        evidence=[
            "Beaconing behavior detected (see related finding)",
            f"Source host(s): {beacon.source_ips[:5]}",
            f"Destination C2 candidate(s): {beacon.destination_ips[:5]}",
        ],
        remediation=[
            "Block all outbound traffic to the identified destination IPs/domains.",
            "Capture additional traffic samples for full payload analysis.",
            "Conduct endpoint forensic investigation on the beaconing host.",
            "Scan endpoint with updated antimalware and EDR tools.",
        ],
        timestamp=beacon.timestamp,
        source_ips=beacon.source_ips,
        destination_ips=beacon.destination_ips,
        category="Correlation",
    )]


def _correlate_reconnaissance(findings: List[Finding]) -> List[Finding]:
    has_port_scan = any("Port Scan" in f.title for f in findings)
    if not has_port_scan:
        return []

    scan = next(f for f in findings if "Port Scan" in f.title)

    return [Finding(
        finding_id=generate_id("CORR"),
        title="Possible Active Reconnaissance",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        mitre_attacks=[
            MitreAttack("T1046", "Network Service Discovery"),
            MitreAttack("T1595", "Active Scanning"),
        ],
        description=(
            "Rapid port probing with failed connection patterns indicates active network "
            "reconnaissance. The threat actor is mapping exposed services to identify "
            "exploitable attack surfaces."
        ),
        evidence=[
            "Port scan activity detected (see related finding)",
            f"Reconnaissance source IP(s): {scan.source_ips[:5]}",
        ],
        remediation=[
            "Block the scanning IP at the perimeter firewall.",
            "Enable port scan detection signatures on your IDS/IPS.",
            "Audit firewall rules to minimize unnecessary exposed services.",
        ],
        timestamp=scan.timestamp,
        source_ips=scan.source_ips,
        category="Correlation",
    )]


def _correlate_data_exfiltration(findings: List[Finding]) -> List[Finding]:
    has_dns_tunnel = any("DNS Tunneling" in f.title for f in findings)
    if not has_dns_tunnel:
        return []

    dns = next(f for f in findings if "DNS Tunneling" in f.title)

    return [Finding(
        finding_id=generate_id("CORR"),
        title="Possible Data Exfiltration via DNS",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        mitre_attacks=[
            MitreAttack("T1071.004", "Application Layer Protocol: DNS"),
            MitreAttack("T1041", "Exfiltration Over C2 Channel"),
            MitreAttack("T1048", "Exfiltration Over Alternative Protocol"),
        ],
        description=(
            "DNS tunneling patterns suggest active or ongoing data exfiltration. Encoded data "
            "embedded in DNS query names bypasses many perimeter controls that permit outbound "
            "DNS traffic, making this a common covert exfiltration technique."
        ),
        evidence=[
            "DNS tunneling pattern detected (see related finding)",
            f"Source host(s): {dns.source_ips[:5]}",
        ],
        remediation=[
            "Immediately block or null-route suspicious DNS destination domains.",
            "Deploy DNS inspection, RPZ filtering, or a DNS security gateway.",
            "Assess the scope and content of potentially exfiltrated data.",
            "Investigate source endpoints for DNS tunneling tools (iodine, dnscat2, etc.).",
            "Tighten DNS egress policies to restrict permitted resolvers.",
        ],
        timestamp=dns.timestamp,
        source_ips=dns.source_ips,
        category="Correlation",
    )]
