from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    flags: Optional[str] = None
    payload: Optional[bytes] = None


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    start_time: float
    end_time: float
    packets: List[PacketInfo] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def packet_count(self) -> int:
        return len(self.packets)


@dataclass
class MitreAttack:
    technique_id: str
    technique_name: str


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: Severity
    confidence: Confidence
    mitre_attacks: List[MitreAttack]
    description: str
    evidence: List[str]
    remediation: List[str]
    timestamp: float
    source_ips: List[str] = field(default_factory=list)
    destination_ips: List[str] = field(default_factory=list)
    category: str = ""
    severity_order: int = 99


@dataclass
class AnalysisResult:
    pcap_file: str
    analysis_start: float
    analysis_end: float
    total_packets: int
    total_flows: int
    findings: List[Finding] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
