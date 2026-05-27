import time

import pytest

from app.analyzer import run_protocol_analysis
from app.correlation import correlate_threats
from app.detector import (
    _detect_beaconing,
    _detect_packet_size_anomalies,
    _detect_port_scans,
    _detect_traffic_spikes,
    run_signature_detection,
    run_statistical_detection,
)
from app.models import (
    Confidence,
    Finding,
    Flow,
    MitreAttack,
    PacketInfo,
    Severity,
)
from app.utils import calculate_entropy, generate_id


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_packet(
    src_ip="192.168.1.1",
    dst_ip="10.0.0.1",
    src_port=12345,
    dst_port=80,
    protocol="TCP",
    size=500,
    flags="S",
    payload=None,
    timestamp=None,
):
    return PacketInfo(
        timestamp=timestamp or time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        size=size,
        flags=flags,
        payload=payload,
    )


def make_flow(src_ip, dst_ip, start_time, num_connections=1, interval=60.0):
    """Create a single flow object starting at start_time."""
    return Flow(
        flow_id=generate_id("flow"),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        start_time=start_time,
        end_time=start_time + 1.0,
        packets=[make_packet(src_ip=src_ip, dst_ip=dst_ip, timestamp=start_time)],
        total_bytes=500,
    )


def make_finding(title, severity=Severity.MEDIUM, src_ips=None, dst_ips=None, ts=None):
    return Finding(
        finding_id=generate_id("TEST"),
        title=title,
        severity=severity,
        confidence=Confidence.HIGH,
        mitre_attacks=[MitreAttack("T0000", "Test Technique")],
        description="Test finding",
        evidence=[],
        remediation=[],
        timestamp=ts or 1700000000.0,
        source_ips=src_ips or ["192.168.1.1"],
        destination_ips=dst_ips or [],
        category="Test",
    )


# ─── Entropy ─────────────────────────────────────────────────────────────────

class TestEntropy:
    def test_uniform_data_has_zero_entropy(self):
        assert calculate_entropy(bytes([0x41] * 100)) == 0.0

    def test_high_entropy_for_random_data(self):
        import os
        assert calculate_entropy(os.urandom(256)) > 7.0

    def test_empty_bytes_returns_zero(self):
        assert calculate_entropy(b"") == 0.0

    def test_two_byte_values_has_one_bit_entropy(self):
        data = bytes([0x00, 0xFF] * 50)
        assert abs(calculate_entropy(data) - 1.0) < 0.01


# ─── Port Scan Detection ──────────────────────────────────────────────────────

class TestPortScanDetection:
    def test_detects_port_scan_above_threshold(self):
        packets = [make_packet(dst_port=port, flags="S") for port in range(1, 50)]
        findings = _detect_port_scans(packets)
        assert any("Port Scan" in f.title for f in findings)

    def test_no_detection_below_threshold(self):
        packets = [make_packet(dst_port=80, flags="S") for _ in range(10)]
        assert _detect_port_scans(packets) == []

    def test_ack_packets_not_counted_as_scan(self):
        # ACK-only packets should not trigger port scan
        packets = [make_packet(dst_port=port, flags="A") for port in range(1, 50)]
        assert _detect_port_scans(packets) == []

    def test_severity_is_medium(self):
        packets = [make_packet(dst_port=port, flags="S") for port in range(1, 50)]
        findings = _detect_port_scans(packets)
        assert all(f.severity == Severity.MEDIUM for f in findings)

    def test_mitre_t1046_in_findings(self):
        packets = [make_packet(dst_port=port, flags="S") for port in range(1, 50)]
        findings = _detect_port_scans(packets)
        assert any(
            "T1046" in m.technique_id
            for f in findings
            for m in f.mitre_attacks
        )

    def test_source_ip_captured(self):
        packets = [make_packet(src_ip="10.1.2.3", dst_port=port, flags="S") for port in range(1, 50)]
        findings = _detect_port_scans(packets)
        assert any("10.1.2.3" in f.source_ips for f in findings)


# ─── SYN Flood Detection ──────────────────────────────────────────────────────

class TestSynFloodDetection:
    def _flood_packets(self, count=150, dst_ip="10.0.0.1"):
        return [
            make_packet(src_ip=f"1.2.3.{i % 254 + 1}", dst_ip=dst_ip, flags="S")
            for i in range(count)
        ]

    def test_detects_syn_flood(self):
        findings = run_signature_detection(self._flood_packets(), [])
        assert any("SYN Flood" in f.title for f in findings)

    def test_severity_is_high(self):
        findings = run_signature_detection(self._flood_packets(), [])
        flood_findings = [f for f in findings if "SYN Flood" in f.title]
        assert all(f.severity == Severity.HIGH for f in flood_findings)

    def test_below_threshold_not_detected(self):
        findings = run_signature_detection(self._flood_packets(count=50), [])
        assert not any("SYN Flood" in f.title for f in findings)

    def test_destination_ip_captured(self):
        findings = run_signature_detection(self._flood_packets(dst_ip="172.16.0.1"), [])
        flood = [f for f in findings if "SYN Flood" in f.title]
        assert any("172.16.0.1" in f.destination_ips for f in flood)


# ─── Beaconing Detection ──────────────────────────────────────────────────────

class TestBeaconingDetection:
    def test_detects_regular_beaconing(self):
        base = 1700000000.0
        flows = [make_flow("192.168.1.100", "203.0.113.50", base + i * 60.0) for i in range(10)]
        findings = _detect_beaconing(flows)
        assert any("Beaconing" in f.title for f in findings)

    def test_irregular_traffic_not_flagged(self):
        import random
        random.seed(42)
        base = 1700000000.0
        flows = [
            make_flow("192.168.1.100", "203.0.113.50", base + random.uniform(0, 3600))
            for _ in range(10)
        ]
        assert _detect_beaconing(flows) == []

    def test_severity_is_high(self):
        base = 1700000000.0
        flows = [make_flow("192.168.1.100", "203.0.113.50", base + i * 60.0) for i in range(10)]
        findings = _detect_beaconing(flows)
        assert all(f.severity == Severity.HIGH for f in findings if "Beaconing" in f.title)

    def test_source_and_dest_ips_recorded(self):
        base = 1700000000.0
        flows = [make_flow("10.0.0.5", "8.8.8.8", base + i * 30.0) for i in range(10)]
        findings = _detect_beaconing(flows)
        beacon = next(f for f in findings if "Beaconing" in f.title)
        assert "10.0.0.5" in beacon.source_ips
        assert "8.8.8.8" in beacon.destination_ips

    def test_insufficient_flows_not_detected(self):
        base = 1700000000.0
        flows = [make_flow("192.168.1.100", "203.0.113.50", base + i * 60.0) for i in range(3)]
        assert _detect_beaconing(flows) == []


# ─── Traffic Spike Detection ──────────────────────────────────────────────────

class TestTrafficSpikeDetection:
    def test_detects_spike(self):
        base = 1700000000.0
        # 5 packets/sec baseline for 30 seconds
        packets = [make_packet(timestamp=base + i // 5) for i in range(150)]
        # 200 packets in one second spike
        packets += [make_packet(timestamp=base + 31) for _ in range(200)]
        findings = _detect_traffic_spikes(packets)
        assert any("Spike" in f.title for f in findings)

    def test_no_spike_on_uniform_traffic(self):
        base = 1700000000.0
        packets = [make_packet(timestamp=base + i) for i in range(50)]
        assert _detect_traffic_spikes(packets) == []

    def test_requires_minimum_packets(self):
        assert _detect_traffic_spikes([make_packet() for _ in range(5)]) == []


# ─── Packet Size Anomaly Detection ───────────────────────────────────────────

class TestPacketSizeAnomalyDetection:
    def test_detects_large_anomalous_packet(self):
        base = 1700000000.0
        packets = [make_packet(size=500, timestamp=base + i) for i in range(50)]
        packets.append(make_packet(size=60000, timestamp=base + 51))
        findings = _detect_packet_size_anomalies(packets)
        assert any("Anomaly" in f.title for f in findings)

    def test_uniform_sizes_not_flagged(self):
        packets = [make_packet(size=500) for _ in range(50)]
        assert _detect_packet_size_anomalies(packets) == []

    def test_requires_minimum_packet_count(self):
        assert _detect_packet_size_anomalies([make_packet() for _ in range(5)]) == []


# ─── Protocol Analysis ────────────────────────────────────────────────────────

class TestProtocolAnalysis:
    def test_detects_telnet(self):
        packets = [make_packet(dst_port=23, protocol="TCP") for _ in range(5)]
        findings = run_protocol_analysis(packets)
        assert any("Telnet" in f.title for f in findings)

    def test_telnet_severity_is_high(self):
        packets = [make_packet(dst_port=23, protocol="TCP") for _ in range(5)]
        findings = run_protocol_analysis(packets)
        telnet = [f for f in findings if "Telnet" in f.title]
        assert all(f.severity == Severity.HIGH for f in telnet)

    def test_detects_ftp_auth(self):
        packets = [make_packet(dst_port=21, payload=b"USER admin\r\n") for _ in range(3)]
        findings = run_protocol_analysis(packets)
        assert any("FTP" in f.title for f in findings)

    def test_detects_smb1(self):
        packets = [make_packet(dst_port=445, payload=b"\xffSMB\x72\x00\x00") for _ in range(3)]
        findings = run_protocol_analysis(packets)
        assert any("SMBv1" in f.title for f in findings)

    def test_smb1_severity_is_high(self):
        packets = [make_packet(dst_port=445, payload=b"\xffSMB\x72\x00") for _ in range(3)]
        findings = run_protocol_analysis(packets)
        smb = [f for f in findings if "SMBv1" in f.title]
        assert all(f.severity == Severity.HIGH for f in smb)

    def test_detects_http_basic_auth(self):
        packets = [
            make_packet(dst_port=80, payload=b"POST /login HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n")
            for _ in range(3)
        ]
        findings = run_protocol_analysis(packets)
        assert any("HTTP Credential" in f.title for f in findings)

    def test_detects_http_password_form(self):
        packets = [
            make_packet(dst_port=80, payload=b"POST /login HTTP/1.1\r\n\r\nusername=admin&password=secret")
            for _ in range(3)
        ]
        findings = run_protocol_analysis(packets)
        assert any("HTTP Credential" in f.title for f in findings)

    def test_detects_weak_tls_v10(self):
        # TLS record: content_type=0x16, version=0x0301 (TLS 1.0)
        tls_pkt = bytes([0x16, 0x03, 0x01, 0x00, 0x00])
        packets = [make_packet(dst_port=443, payload=tls_pkt) for _ in range(3)]
        findings = run_protocol_analysis(packets)
        assert any("TLS" in f.title for f in findings)

    def test_no_false_positive_on_normal_http(self):
        packets = [make_packet(dst_port=80, payload=b"GET /index.html HTTP/1.1\r\n") for _ in range(5)]
        findings = run_protocol_analysis(packets)
        assert not any("HTTP Credential" in f.title for f in findings)


# ─── Threat Correlation ───────────────────────────────────────────────────────

class TestThreatCorrelation:
    def test_correlates_lateral_movement(self):
        findings = [
            make_finding("Port Scan Detected", Severity.MEDIUM, src_ips=["192.168.1.100"]),
            make_finding("SMB Exploitation Indicators Detected", Severity.HIGH, src_ips=["192.168.1.100"]),
        ]
        correlated = correlate_threats(findings)
        assert any("Lateral Movement" in f.title for f in correlated)

    def test_lateral_movement_severity_high(self):
        findings = [
            make_finding("Port Scan Detected", Severity.MEDIUM),
            make_finding("SMB Exploitation Indicators Detected", Severity.HIGH),
        ]
        correlated = correlate_threats(findings)
        lateral = [f for f in correlated if "Lateral Movement" in f.title]
        assert all(f.severity == Severity.HIGH for f in lateral)

    def test_correlates_c2_from_beaconing(self):
        findings = [
            make_finding(
                "Beaconing Behavior Detected", Severity.HIGH,
                src_ips=["192.168.1.50"], dst_ips=["203.0.113.99"],
            )
        ]
        correlated = correlate_threats(findings)
        assert any("Command & Control" in f.title for f in correlated)

    def test_no_lateral_movement_without_smb(self):
        findings = [make_finding("Port Scan Detected", Severity.MEDIUM)]
        correlated = correlate_threats(findings)
        assert not any("Lateral Movement" in f.title for f in correlated)

    def test_correlates_dns_exfiltration(self):
        findings = [make_finding("DNS Tunneling Pattern Detected", Severity.CRITICAL)]
        correlated = correlate_threats(findings)
        assert any("Exfiltration" in f.title for f in correlated)

    def test_exfiltration_severity_critical(self):
        findings = [make_finding("DNS Tunneling Pattern Detected", Severity.CRITICAL)]
        correlated = correlate_threats(findings)
        exfil = [f for f in correlated if "Exfiltration" in f.title]
        assert all(f.severity == Severity.CRITICAL for f in exfil)

    def test_correlates_reconnaissance(self):
        findings = [make_finding("Port Scan Detected", Severity.MEDIUM)]
        correlated = correlate_threats(findings)
        assert any("Reconnaissance" in f.title for f in correlated)

    def test_no_c2_without_beaconing(self):
        findings = [make_finding("Traffic Volume Spike Detected", Severity.MEDIUM)]
        correlated = correlate_threats(findings)
        assert not any("Command & Control" in f.title for f in correlated)


# ─── Finding Model ────────────────────────────────────────────────────────────

class TestFindingModel:
    def test_finding_has_required_fields(self):
        f = make_finding("Test Finding")
        assert f.finding_id
        assert f.title
        assert f.severity
        assert f.confidence
        assert f.mitre_attacks
        assert f.description
        assert isinstance(f.evidence, list)
        assert isinstance(f.remediation, list)

    def test_severity_ordering(self):
        from app.reporting import SEVERITY_ORDER
        assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["HIGH"]
        assert SEVERITY_ORDER["HIGH"] < SEVERITY_ORDER["MEDIUM"]
        assert SEVERITY_ORDER["MEDIUM"] < SEVERITY_ORDER["LOW"]
