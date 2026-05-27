import os

from dotenv import load_dotenv

load_dotenv()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
MAX_PCAP_SIZE_GB = float(os.getenv("MAX_PCAP_SIZE_GB", "5"))
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", "reports/")
ENABLE_TLS_ANALYSIS = os.getenv("ENABLE_TLS_ANALYSIS", "true").lower() == "true"
ENABLE_DNS_ANALYSIS = os.getenv("ENABLE_DNS_ANALYSIS", "true").lower() == "true"

PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))
SYN_FLOOD_THRESHOLD = int(os.getenv("SYN_FLOOD_THRESHOLD", "100"))
DNS_QUERY_LENGTH_THRESHOLD = int(os.getenv("DNS_QUERY_LENGTH_THRESHOLD", "50"))
BEACON_INTERVAL_TOLERANCE = float(os.getenv("BEACON_INTERVAL_TOLERANCE", "0.1"))
TRAFFIC_SPIKE_MULTIPLIER = float(os.getenv("TRAFFIC_SPIKE_MULTIPLIER", "3.0"))

SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 6667, 6666, 1234, 9999, 8888,
    12345, 54321, 5555, 7777, 2222, 3333,
}
