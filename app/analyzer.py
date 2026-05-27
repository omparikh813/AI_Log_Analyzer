from collections import defaultdict
from typing import List

from app.models import Confidence, Finding, MitreAttack, PacketInfo, Severity
from app.utils import calculate_entropy, generate_id, setup_logging

logger = setup_logging(__name__)

WEAK_TLS_VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1"}
SMB_PORTS = {445, 139}
FTP_PORT = 21
TELNET_PORT = 23
HTTP_PORT = 80


def run_protocol_analysis(packets: List[PacketInfo]) -> List[Finding]:
    from config import ENABLE_DNS_ANALYSIS, ENABLE_TLS_ANALYSIS

    findings: List[Finding] = []

    if ENABLE_TLS_ANALYSIS:
        findings.extend(_analyze_tls(packets))

    findings.extend(_analyze_smb(packets))
    findings.extend(_analyze_ftp_telnet(packets))
    findings.extend(_analyze_http_credentials(packets))

    if ENABLE_DNS_ANALYSIS:
        findings.extend(_analyze_dns_tunneling(packets))

    return findings


def _analyze_tls(packets: List[PacketInfo]) -> List[Finding]:
    """Detect deprecated TLS versions via raw ClientHello record inspection."""
    findings: List[Finding] = []
    weak_sessions: dict = defaultdict(list)

    for pkt in packets:
        if not pkt.payload or pkt.dst_port not in {443, 8443}:
            continue
        # TLS record layer: byte 0 = content type 0x16 (handshake), bytes 1-2 = version
        if len(pkt.payload) >= 3 and pkt.payload[0] == 0x16:
            version = (pkt.payload[1] << 8) | pkt.payload[2]
            if version in WEAK_TLS_VERSIONS:
                weak_sessions[WEAK_TLS_VERSIONS[version]].append(pkt)

    for version_name, pkts in weak_sessions.items():
        sources = list({p.src_ip for p in pkts})
        findings.append(Finding(
            finding_id=generate_id("PROTO"),
            title=f"Weak TLS Version in Use: {version_name}",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            mitre_attacks=[MitreAttack("T1040", "Network Sniffing")],
            description=(
                f"{version_name} is deprecated and vulnerable to known cryptographic attacks "
                f"(POODLE, BEAST, DROWN). Detected in {len(pkts)} packets from {len(sources)} host(s)."
            ),
            evidence=[
                f"Deprecated TLS version: {version_name}",
                f"Affected source IPs: {sources[:5]}",
                f"Packet count using this version: {len(pkts)}",
            ],
            remediation=[
                f"Disable {version_name} on all servers and clients.",
                "Enforce TLS 1.2 as the minimum; prefer TLS 1.3.",
                "Update SSL/TLS libraries and server configurations.",
                "Run SSL Labs or similar scanner to audit TLS configuration.",
            ],
            timestamp=pkts[0].timestamp,
            source_ips=sources,
            category="Protocol",
        ))
    return findings


def _analyze_smb(packets: List[PacketInfo]) -> List[Finding]:
    """Detect SMBv1 usage via magic bytes in packet payload."""
    findings: List[Finding] = []
    smb1_packets = []

    for pkt in packets:
        if pkt.dst_port not in SMB_PORTS or not pkt.payload:
            continue
        # SMBv1 magic: \xffSMB
        if len(pkt.payload) >= 4 and pkt.payload[:4] == b"\xffSMB":
            smb1_packets.append(pkt)

    if smb1_packets:
        sources = list({p.src_ip for p in smb1_packets})
        dests = list({p.dst_ip for p in smb1_packets})
        findings.append(Finding(
            finding_id=generate_id("PROTO"),
            title="SMBv1 Protocol Usage Detected",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            mitre_attacks=[
                MitreAttack("T1210", "Exploitation of Remote Services"),
                MitreAttack("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
            ],
            description=(
                f"SMBv1 traffic detected in {len(smb1_packets)} packets. SMBv1 is deprecated "
                "and directly exploitable via EternalBlue (MS17-010), the vulnerability used "
                "by WannaCry and NotPetya ransomware campaigns."
            ),
            evidence=[
                f"SMBv1 packet count: {len(smb1_packets)}",
                f"Source hosts: {sources[:5]}",
                f"Target hosts: {dests[:5]}",
            ],
            remediation=[
                "Disable SMBv1 on all Windows hosts via Group Policy or PowerShell.",
                "Apply MS17-010 security patches immediately if not already done.",
                "Segment internal SMB traffic with firewall rules.",
                "Enable SMB signing to mitigate relay attacks.",
            ],
            timestamp=smb1_packets[0].timestamp,
            source_ips=sources,
            destination_ips=dests,
            category="Protocol",
        ))
    return findings


def _analyze_ftp_telnet(packets: List[PacketInfo]) -> List[Finding]:
    """Detect cleartext FTP authentication and Telnet session traffic."""
    findings: List[Finding] = []
    ftp_auth_packets = []
    telnet_packets = []

    for pkt in packets:
        if pkt.dst_port == TELNET_PORT:
            telnet_packets.append(pkt)
            continue

        if not pkt.payload:
            continue

        try:
            payload_str = pkt.payload.decode("latin-1", errors="ignore")
        except Exception:
            continue

        if pkt.dst_port == FTP_PORT and any(
            cmd in payload_str.upper() for cmd in ("USER ", "PASS ")
        ):
            ftp_auth_packets.append(pkt)

    if ftp_auth_packets:
        sources = list({p.src_ip for p in ftp_auth_packets})
        findings.append(Finding(
            finding_id=generate_id("PROTO"),
            title="FTP Cleartext Authentication Detected",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            mitre_attacks=[
                MitreAttack("T1552.001", "Unsecured Credentials: Credentials In Files"),
                MitreAttack("T1040", "Network Sniffing"),
            ],
            description=(
                f"FTP USER/PASS commands observed in cleartext across {len(ftp_auth_packets)} packets. "
                "Any on-path observer can trivially capture these credentials."
            ),
            evidence=[
                f"FTP authentication packet count: {len(ftp_auth_packets)}",
                f"Source IPs: {sources[:5]}",
            ],
            remediation=[
                "Replace FTP with SFTP (SSH File Transfer) or FTPS (FTP over TLS).",
                "Rotate any credentials that were transmitted in plaintext.",
                "Block inbound/outbound FTP at the perimeter firewall.",
            ],
            timestamp=ftp_auth_packets[0].timestamp,
            source_ips=sources,
            category="Protocol",
        ))

    if telnet_packets:
        sources = list({p.src_ip for p in telnet_packets})
        dests = list({p.dst_ip for p in telnet_packets})
        findings.append(Finding(
            finding_id=generate_id("PROTO"),
            title="Telnet Usage Detected (Cleartext Protocol)",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            mitre_attacks=[
                MitreAttack("T1557", "Adversary-in-the-Middle"),
                MitreAttack("T1040", "Network Sniffing"),
            ],
            description=(
                f"Telnet sessions observed in {len(telnet_packets)} packets. Telnet transmits "
                "all data—including credentials and session content—in cleartext, enabling "
                "trivial credential theft by any on-path attacker."
            ),
            evidence=[
                f"Telnet packet count: {len(telnet_packets)}",
                f"Source IPs: {sources[:5]}",
                f"Destination IPs: {dests[:5]}",
            ],
            remediation=[
                "Disable the Telnet service on all network devices and hosts.",
                "Replace Telnet with SSH for all remote management.",
                "Rotate all credentials that may have been used over Telnet.",
                "Audit affected systems for signs of unauthorized access.",
            ],
            timestamp=telnet_packets[0].timestamp,
            source_ips=sources,
            destination_ips=dests,
            category="Protocol",
        ))

    return findings


def _analyze_http_credentials(packets: List[PacketInfo]) -> List[Finding]:
    """Detect HTTP Basic Auth headers and form-based password submissions."""
    findings: List[Finding] = []
    cred_packets = []

    for pkt in packets:
        if pkt.dst_port != HTTP_PORT or not pkt.payload:
            continue

        try:
            payload_str = pkt.payload.decode("latin-1", errors="ignore")
        except Exception:
            continue

        if "Authorization: Basic" in payload_str or any(
            kw in payload_str.lower() for kw in ("password=", "passwd=", "pwd=")
        ):
            cred_packets.append(pkt)

    if cred_packets:
        sources = list({p.src_ip for p in cred_packets})
        findings.append(Finding(
            finding_id=generate_id("PROTO"),
            title="HTTP Credential Leak Detected",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            mitre_attacks=[
                MitreAttack("T1552.001", "Unsecured Credentials: Credentials In Files"),
                MitreAttack("T1040", "Network Sniffing"),
            ],
            description=(
                f"Authentication credentials or tokens detected in {len(cred_packets)} unencrypted "
                "HTTP packets. These are fully visible to any network observer or MITM attacker."
            ),
            evidence=[
                f"HTTP credential packet count: {len(cred_packets)}",
                f"Source IPs: {sources[:5]}",
            ],
            remediation=[
                "Enforce HTTPS across all web applications; redirect HTTP to HTTPS.",
                "Implement HTTP Strict Transport Security (HSTS) headers.",
                "Rotate all credentials observed in unencrypted traffic.",
                "Audit web application login flows for HTTPS enforcement.",
            ],
            timestamp=cred_packets[0].timestamp,
            source_ips=sources,
            category="Protocol",
        ))
    return findings


def _analyze_dns_tunneling(packets: List[PacketInfo]) -> List[Finding]:
    """Detect DNS tunneling via payload length and entropy heuristics."""
    from config import DNS_QUERY_LENGTH_THRESHOLD

    findings: List[Finding] = []
    suspicious: list = []

    for pkt in packets:
        if pkt.dst_port != 53 or not pkt.payload:
            continue
        if len(pkt.payload) > DNS_QUERY_LENGTH_THRESHOLD:
            entropy = calculate_entropy(pkt.payload)
            if entropy > 3.5:
                suspicious.append((pkt, entropy))

    if len(suspicious) >= 3:
        sources = list({p.src_ip for p, _ in suspicious})
        avg_entropy = sum(e for _, e in suspicious) / len(suspicious)
        findings.append(Finding(
            finding_id=generate_id("PROTO"),
            title="DNS Tunneling Pattern Detected",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            mitre_attacks=[
                MitreAttack("T1071.004", "Application Layer Protocol: DNS"),
                MitreAttack("T1041", "Exfiltration Over C2 Channel"),
            ],
            description=(
                f"Detected {len(suspicious)} DNS packets with unusually long, high-entropy payloads "
                f"(average entropy: {avg_entropy:.2f} bits/byte, threshold: 3.5). "
                "This pattern is consistent with DNS tunneling tools (iodine, dnscat2) used for "
                "covert data exfiltration or C2 communication."
            ),
            evidence=[
                f"Suspicious DNS packet count: {len(suspicious)}",
                f"Average payload entropy: {avg_entropy:.2f} bits/byte",
                f"Source IPs: {sources[:5]}",
                f"Largest payload observed: {max(len(p.payload) for p, _ in suspicious)} bytes",
            ],
            remediation=[
                "Block or sinkhole the suspicious destination domains at your DNS resolver.",
                "Deploy DNS security filtering (RPZ, DNS firewall, or equivalent).",
                "Investigate source endpoints for DNS tunneling tools.",
                "Quantify potential data exfiltration volume from DNS query logs.",
            ],
            timestamp=suspicious[0][0].timestamp,
            source_ips=sources,
            category="Protocol",
        ))
    return findings
