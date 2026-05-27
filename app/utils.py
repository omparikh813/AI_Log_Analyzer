import logging
import math
import os
import sys
import time
import uuid


def setup_logging(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        logger.addHandler(handler)
    from config import LOG_LEVEL
    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
    return logger


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def ensure_output_dir(path: str):
    os.makedirs(path, exist_ok=True)


def format_timestamp(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def generate_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
