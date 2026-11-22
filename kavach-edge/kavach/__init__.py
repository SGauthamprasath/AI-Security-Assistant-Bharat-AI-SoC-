"""Kavach-Edge: on-device threat, phishing & scam detection (Bharat AI-SoC PS3).

Everything in this package runs locally with only NumPy (+ optional SciPy/scapy for
training / pcap parsing).  No module here opens a network connection - this is
enforced by tests (tests/test_offline.py) and by offline_proof/verify_offline.py.
"""

__version__ = "1.0.0"
SCHEMA_VERSION = "kavach.evidence/1.0"
