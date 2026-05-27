import sys
import time
from collections import defaultdict
from typing import List

from app.analyzer import run_protocol_analysis
from app.correlation import correlate_threats
from app.detector import run_signature_detection, run_statistical_detection
from app.models import AnalysisResult, Finding
from app.parser import parse_pcap
from app.reporting import generate_reports
from app.utils import setup_logging

logger = setup_logging("main")


def analyze(pcap_path: str) -> AnalysisResult:
    start_time = time.time()
    logger.info(f"Starting PCAP analysis: {pcap_path}")

    packets, flows = parse_pcap(pcap_path)

    findings: List[Finding] = []
    findings.extend(run_signature_detection(packets, flows))
    findings.extend(run_statistical_detection(packets, flows))
    findings.extend(run_protocol_analysis(packets))
    findings.extend(correlate_threats(findings))

    end_time = time.time()

    result = AnalysisResult(
        pcap_file=pcap_path,
        analysis_start=start_time,
        analysis_end=end_time,
        total_packets=len(packets),
        total_flows=len(flows),
        findings=findings,
        timeline=_build_timeline(findings, packets),
        statistics=_compute_statistics(packets, flows),
    )

    logger.info(
        f"Analysis complete: {len(findings)} findings, "
        f"{len(packets)} packets, {len(flows)} flows in {end_time - start_time:.2f}s"
    )
    return result


def _build_timeline(findings: List[Finding], packets) -> list:
    events = []
    if packets:
        events.append({"timestamp": packets[0].timestamp, "event": "Capture Start", "detail": ""})
        events.append({"timestamp": packets[-1].timestamp, "event": "Capture End", "detail": ""})
    for f in findings:
        events.append({"timestamp": f.timestamp, "event": f.title, "detail": f.severity.value})
    return sorted(events, key=lambda e: e["timestamp"])


def _compute_statistics(packets, flows) -> dict:
    if not packets:
        return {}
    proto_dist: dict = defaultdict(int)
    for p in packets:
        proto_dist[p.protocol] += 1
    return {
        "capture_duration_seconds": round(packets[-1].timestamp - packets[0].timestamp, 2)
        if len(packets) > 1 else 0,
        "avg_packet_size_bytes": round(sum(p.size for p in packets) / len(packets), 1),
        "protocol_distribution": dict(sorted(proto_dist.items(), key=lambda x: x[1], reverse=True)),
        "unique_source_ips": len({p.src_ip for p in packets}),
        "unique_destination_ips": len({p.dst_ip for p in packets}),
        "total_bytes": sum(p.size for p in packets),
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <pcap_file>")
        print("       python -m app.main sample_pcaps/example.pcap")
        sys.exit(1)

    pcap_path = sys.argv[1]
    result = analyze(pcap_path)
    paths = generate_reports(result)

    print(f"\n{'=' * 60}")
    print("PCAP Threat Analyzer — Analysis Complete")
    print(f"{'=' * 60}")
    print(f"  File:     {result.pcap_file}")
    print(f"  Packets:  {result.total_packets}")
    print(f"  Flows:    {result.total_flows}")
    print(f"  Findings: {len(result.findings)}")
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sum(1 for f in result.findings if f.severity.value == sev)
        if count:
            print(f"  [{sev:<8}] {count}")
    print()
    print("  Reports:")
    for fmt, path in paths.items():
        print(f"    [{fmt.upper()}] {path}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
