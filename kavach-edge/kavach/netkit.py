"""Network-intrusion detection: NSL-KDD feature schema, deployable subset and runtime model.

Deployable subset
-----------------
NSL-KDD has 41 features, 13 of which ("content" features: failed logins, root shell, ...) need deep
packet / payload inspection that a phone or Pi cannot do cheaply, or at all for encrypted traffic.
We keep the 28 features that can be computed from connection metadata alone:
  9 basic  +  9 time-window traffic  +  10 host-window traffic.
Training both variants and reporting the difference is part of the evaluation (honesty over hype).
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

import numpy as np

from .treeexport import TreeRuntime

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

ALL_COLS = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
            "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
            "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
            "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
            "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]
CONTENT = ["hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
           "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login"]
DEPLOY_COLS = [c for c in ALL_COLS if c not in CONTENT]  # 28
PROTOCOLS = ["tcp", "udp", "icmp"]
FLAGS = ["SF", "S0", "REJ", "RSTR", "RSTO", "SH", "S1", "S2", "S3", "OTH", "RSTOS0"]
CLASSES = ["normal", "dos", "probe", "r2l", "u2r"]

ATTACK_CATEGORY = {
    **{a: "dos" for a in "back land neptune pod smurf teardrop mailbomb apache2 processtable udpstorm".split()},
    **{a: "probe" for a in "satan ipsweep nmap portsweep mscan saint".split()},
    **{a: "r2l" for a in "ftp_write guess_passwd imap multihop phf spy warezclient warezmaster xlock xsnoop snmpguess snmpgetattack httptunnel sendmail named worm".split()},
    **{a: "u2r" for a in "buffer_overflow loadmodule perl rootkit ps sqlattack xterm".split()},
    "normal": "normal",
}

EXPLAIN = {
    "dos": ("Flood of connection attempts (denial-of-service)", "A device is sending a flood of connection requests that can slow down or knock out a device or the router.",
            ("ISOLATE_DEVICE", "RESTART_ROUTER", "CHECK_ROUTER_LOGS")),
    "probe": ("Port scanning / network probing", "Someone or something is systematically knocking on many doors (ports) of your devices to find weak spots.",
              ("ISOLATE_DEVICE", "CHANGE_ROUTER_PASSWORD", "CHECK_ROUTER_LOGS")),
    "r2l": ("Unauthorised remote access attempt", "A remote machine appears to be trying to log in or gain access without permission.",
            ("CHANGE_PASSWORDS", "ISOLATE_DEVICE", "CHECK_ROUTER_LOGS")),
    "u2r": ("Privilege-escalation behaviour", "A program on a device appears to be trying to gain administrator-level control.",
            ("ISOLATE_DEVICE", "CHANGE_PASSWORDS", "RUN_MALWARE_SCAN")),
}


def encode_row(row: Dict[str, object], meta: Dict) -> np.ndarray:
    """dict(column -> value) -> numeric vector in DEPLOY_COLS order."""
    svc = meta["services"]
    out = []
    for c in DEPLOY_COLS:
        v = row[c]
        if c == "protocol_type":
            v = PROTOCOLS.index(v) if v in PROTOCOLS else -1
        elif c == "service":
            v = svc.index(v) if v in svc else svc.index("other") if "other" in svc else -1
        elif c == "flag":
            v = FLAGS.index(v) if v in FLAGS else FLAGS.index("OTH")
        out.append(float(v))
    return np.asarray(out, np.float64)


class NetModel:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.rt = TreeRuntime(os.path.join(model_dir, "net_hgb.npz"))
        self.meta = json.load(open(os.path.join(model_dir, "net_meta.json")))
        self.a, self.b = self.meta["calib"]["a"], self.meta["calib"]["b"]
        self.size_bytes = self.rt.size_bytes

    def predict(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        P = self.rt.predict_proba(X)  # n x 5
        p_attack = 1.0 - P[:, 0]
        p_attack = np.clip(p_attack, 1e-6, 1 - 1e-6)
        z = np.log(p_attack / (1 - p_attack))
        zc = self.a * z + self.b
        return {"proba": P, "logit": zc, "p_attack": 1 / (1 + np.exp(-zc))}
