import os
from collections import defaultdict
from typing import Dict, List, Tuple

from scapy.all import IP, IPv6, Raw, TCP, UDP, rdpcap

from app.models import Flow, PacketInfo
from app.utils import generate_id, setup_logging

logger = setup_logging(__name__)


def parse_pcap(filepath: str) -> Tuple[List[PacketInfo], List[Flow]]:
    """Parse a PCAP file and return packet metadata and reconstructed flows."""
    from config import MAX_PCAP_SIZE_GB

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    size = os.path.getsize(filepath)
    max_bytes = int(MAX_PCAP_SIZE_GB * 1024 ** 3)
    if size > max_bytes:
        raise ValueError(f"PCAP file exceeds max allowed size ({MAX_PCAP_SIZE_GB} GB)")

    logger.info(f"Parsing PCAP: {filepath} ({size / 1024:.1f} KB)")

    raw_packets = rdpcap(filepath)
    packet_infos: List[PacketInfo] = []

    for pkt in raw_packets:
        info = _extract_packet_info(pkt)
        if info:
            packet_infos.append(info)

    logger.info(f"Extracted {len(packet_infos)} packets")
    flows = _reconstruct_flows(packet_infos)
    logger.info(f"Reconstructed {len(flows)} flows")

    return packet_infos, flows


def _extract_packet_info(pkt) -> PacketInfo | None:
    try:
        timestamp = float(pkt.time)

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto_num = pkt[IPv6].nh
        else:
            return None

        src_port = dst_port = None
        flags = None
        protocol = _proto_name(proto_num)

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
            protocol = "TCP"
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"

        payload = bytes(pkt[Raw].load) if Raw in pkt else None

        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size=len(pkt),
            flags=flags,
            payload=payload,
        )
    except Exception as e:
        logger.debug(f"Skipping malformed packet: {e}")
        return None


def _proto_name(proto_num: int) -> str:
    mapping = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
    return mapping.get(proto_num, f"PROTO_{proto_num}")


def _reconstruct_flows(packets: List[PacketInfo]) -> List[Flow]:
    """Group packets into bidirectional flows by 5-tuple."""
    flow_map: Dict[str, Flow] = {}

    for pkt in packets:
        key = _flow_key(pkt)

        if key not in flow_map:
            flow_map[key] = Flow(
                flow_id=generate_id("flow"),
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
            )

        flow = flow_map[key]
        flow.packets.append(pkt)
        flow.total_bytes += pkt.size
        flow.end_time = max(flow.end_time, pkt.timestamp)

    return list(flow_map.values())


def _flow_key(pkt: PacketInfo) -> str:
    endpoints = sorted([
        (pkt.src_ip, pkt.src_port or 0),
        (pkt.dst_ip, pkt.dst_port or 0),
    ])
    return f"{pkt.protocol}:{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"
