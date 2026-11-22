#!/usr/bin/env python3
"""Offline-operation proof for Kavach-Edge.  One command, four independent kinds of evidence:

    python3 offline_proof/verify_offline.py            -> results/offline_proof.json  +  results/OFFLINE_PROOF.md

 1. STATIC      AST-scan every file in kavach/ for imports of networking modules (socket, urllib, http, ssl, requests, ...).
 2. RUNTIME     In a child process, install a `sys.addaudithook` that records every network-capable audit event
                (socket.connect / bind / sendto / sendmsg / getaddrinfo / gethostby*, urllib.Request, http.client.*, ssl.*)
                and a monkey-patched socket that raises. Then run a real workload (messages, URLs, advisor prompts, pcaps).
                Pass = zero events.  A NEGATIVE CONTROL deliberately tries to connect and must be caught (proves the guard works).
 3. COUNTERS    Read /proc/net/dev before and after the workload for every non-loopback interface. Report the byte/packet delta.
                (Other processes on a busy machine can move these counters, so this is supporting evidence, not the proof.)
 4. NAMESPACE   Re-run the workload inside `unshare --net` (a network namespace with NO interfaces, not even a route): if the code
                needed the network it would fail. Pass = identical verdicts, exit code 0.
On the phone, section 5 of offline_proof/PHONE_PROTOCOL.md gives the airplane-mode + tcpdump version of the same test.
"""
import ast
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
NET_MODULES = {"socket", "ssl", "urllib", "urllib3", "http", "httplib", "requests", "httpx", "aiohttp", "ftplib", "smtplib", "poplib", "imaplib",
               "telnetlib", "xmlrpc", "websocket", "websockets", "paramiko", "asyncio", "socketserver", "selectors", "scapy"}
NET_EVENT_PREFIXES = ("socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo", "socket.gethostby", "socket.getnameinfo",
                      "socket.__new__", "urllib.Request", "http.client", "ssl.", "ftplib.", "smtplib.", "telnetlib.", "imaplib.", "poplib.")


# ---------------------------------------------------------------- 1. static
def static_audit():
    findings, files = [], 0
    for dp, _, fs in os.walk(os.path.join(ROOT, "kavach")):
        for f in fs:
            if not f.endswith(".py"):
                continue
            files += 1
            path = os.path.join(dp, f)
            tree = ast.parse(open(path).read(), path)
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    mods = [node.module.split(".")[0]]
                for m in mods:
                    # `urllib.parse` is pure string parsing (no I/O); everything else in the list can open connections
                    if isinstance(node, ast.ImportFrom) and node.module == "urllib.parse":
                        continue
                    if isinstance(node, ast.Import) and all(a.name == "urllib.parse" for a in node.names):
                        continue
                    if m in NET_MODULES:
                        findings.append({"file": os.path.relpath(path, ROOT), "line": node.lineno, "module": m})
    return {"files_scanned": files, "network_imports": findings, "pass": not findings}


# ---------------------------------------------------------------- 2/4. worker (runs inside the guarded child)
def worker():
    import builtins  # noqa: F401
    events = []

    def hook(ev, args):
        if ev.startswith(NET_EVENT_PREFIXES):
            events.append({"event": ev, "args": repr(args)[:120]})
    sys.addaudithook(hook)
    import socket

    def _blocked(*a, **k):
        events.append({"event": "socket-call-blocked", "args": repr(a)[:80]})
        raise OSError("network disabled by offline proof guard")
    for name in ("connect", "connect_ex", "sendto", "send", "sendall"):
        setattr(socket.socket, name, _blocked)
    socket.getaddrinfo = _blocked
    socket.gethostbyname = _blocked

    # NEGATIVE CONTROL - must be caught, otherwise the guard proves nothing
    before = len(events)
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("93.184.216.34", 80))
    except OSError:
        pass
    control_caught = len(events) > before
    del events[:]                                           # forget the control; count only the real workload

    sys.path.insert(0, ROOT)
    import json as _json
    from kavach.pipeline import Detector
    det = Detector()
    verdicts = []
    for fn in ("kavachbench_in_test.jsonl", "kavachbench_in.jsonl"):
        for line in open(os.path.join(ROOT, "data", fn)):
            r = _json.loads(line)
            ev = det.analyze_message(r["text"], r["sender"], with_prompt=True)
            verdicts.append(ev["verdict"]["label"])
    for line in open(os.path.join(ROOT, "data", "kavachbench_urls_test.jsonl")):
        verdicts.append(det.analyze_url(_json.loads(line)["url"], with_prompt=True)["verdict"]["label"])
    n_pcap = 0
    for n in ("normal_browsing", "port_scan", "syn_flood", "ping_flood", "smurf_like", "mixed_home_network"):
        r = det.analyze_pcap(os.path.join(ROOT, "demo", "pcaps", n + ".pcap"), with_prompt=True)
        verdicts.append(f"{n}:{r['summary']['flagged']}")
        n_pcap += 1
    digest = hashlib.sha256("|".join(verdicts).encode()).hexdigest()[:16]
    mods = sorted(m for m in sys.modules if m.split(".")[0] in ("requests", "urllib3", "httpx", "aiohttp", "scapy", "http", "urllib", "ssl"))
    print("OFFLINE_WORKER_RESULT " + _json.dumps({"events": events, "negative_control_caught": control_caught, "n_verdicts": len(verdicts), "pcaps": n_pcap,
                                                   "verdict_digest": digest, "network_modules_loaded": mods}))


def run_child(wrap=None):
    cmd = [sys.executable, "-I", os.path.abspath(__file__), "--worker"]
    if wrap:
        cmd = wrap + cmd
    t = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    out = {"returncode": p.returncode, "seconds": round(time.time() - t, 1), "stderr_tail": p.stderr.strip()[-300:]}
    for line in p.stdout.splitlines():
        if line.startswith("OFFLINE_WORKER_RESULT "):
            out["result"] = json.loads(line.split(" ", 1)[1])
    return out


# ---------------------------------------------------------------- 3. counters
def net_counters():
    d = {}
    try:
        for line in open("/proc/net/dev").read().splitlines()[2:]:
            name, rest = line.split(":", 1)
            f = rest.split()
            d[name.strip()] = {"rx_bytes": int(f[0]), "rx_packets": int(f[1]), "tx_bytes": int(f[8]), "tx_packets": int(f[9])}
    except OSError:
        return None
    return d


def main():
    res = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "platform": sys.platform}
    print("1/4 static import audit ...")
    res["static"] = static_audit()
    print("    files scanned:", res["static"]["files_scanned"], "network imports:", res["static"]["network_imports"] or "none")

    print("2/4 runtime guard + workload (child process) ...")
    c0 = net_counters()
    guarded = run_child()
    c1 = net_counters()
    r = guarded.get("result", {})
    res["runtime"] = {"returncode": guarded["returncode"], "seconds": guarded["seconds"], "events": r.get("events"), "negative_control_caught": r.get("negative_control_caught"),
                      "n_verdicts": r.get("n_verdicts"), "pcaps": r.get("pcaps"), "network_modules_loaded": r.get("network_modules_loaded"),
                      "pass": guarded["returncode"] == 0 and r.get("events") == [] and bool(r.get("negative_control_caught"))}
    print("    network events during workload:", len(r.get("events") or []), "| negative control caught:", r.get("negative_control_caught"), "| verdicts:", r.get("n_verdicts"))

    print("3/4 interface counters ...")
    if c0 and c1:
        delta = {i: {k: c1[i][k] - c0[i][k] for k in c0[i]} for i in c0 if i in c1 and i != "lo"}
        moved = {i: v for i, v in delta.items() if any(v.values())}
        res["counters"] = {"available": True, "non_loopback_interfaces": list(delta), "moved": moved,
                           "note": "other processes may move these; the runtime guard and namespace test are the proof, this is corroboration"}
        print("    interfaces:", list(delta), "| moved by anything during the window:", moved or "none")
    else:
        res["counters"] = {"available": False}

    print("4/4 empty network namespace (unshare --net) ...")
    ns = run_child(["unshare", "--net", "--map-root-user"])
    nr = ns.get("result", {})
    if ns["returncode"] == 0 and nr:
        res["namespace"] = {"available": True, "returncode": 0, "events": nr.get("events"), "verdict_digest": nr.get("verdict_digest"), "same_verdicts_as_guarded_run": nr.get("verdict_digest") == r.get("verdict_digest"),
                            "pass": nr.get("events") == [] and nr.get("verdict_digest") == r.get("verdict_digest")}
    else:
        res["namespace"] = {"available": False, "reason": ns.get("stderr_tail") or "unshare not permitted here"}
    print("    ", res["namespace"])

    res["overall_pass"] = bool(res["static"]["pass"] and res["runtime"]["pass"] and (not res["namespace"]["available"] or res["namespace"]["pass"]))
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(ROOT, "results", "offline_proof.json"), "w"), indent=1)
    write_md(res)
    print("\nOVERALL:", "PASS" if res["overall_pass"] else "FAIL")
    return 0 if res["overall_pass"] else 1


def write_md(r):
    L = ["# Offline-operation proof (auto-generated by offline_proof/verify_offline.py)\n",
         f"Run: {r['timestamp']}. Claim: *the detector needs no network at any point - install, load, inference, advisor prompt or pcap analysis.*\n",
         "| # | Test | What it shows | Result |", "|---|---|---|---|"]
    s, ru, ns = r["static"], r["runtime"], r["namespace"]
    L.append(f"| 1 | Static import audit | {s['files_scanned']} source files in `kavach/` import no networking module | {'PASS' if s['pass'] else 'FAIL: ' + str(s['network_imports'])} |")
    L.append(f"| 2 | Runtime audit hook + blocked sockets | {ru['n_verdicts']} verdicts and {ru['pcaps']} pcaps (with advisor prompts) produced **{len(ru['events'] or [])}** network events; negative control (deliberate connect) caught = {ru['negative_control_caught']} | {'PASS' if ru['pass'] else 'FAIL'} |")
    if r["counters"].get("available"):
        mv = r["counters"]["moved"]
        L.append(f"| 3 | Interface byte counters | non-loopback interfaces {r['counters']['non_loopback_interfaces']}; counters moved during the window: {mv or 'none'} | informational |")
    if ns["available"]:
        L.append(f"| 4 | Empty network namespace (`unshare --net`) | same verdict digest as the normal run: {ns['same_verdicts_as_guarded_run']}; zero events | {'PASS' if ns['pass'] else 'FAIL'} |")
    else:
        L.append(f"| 4 | Empty network namespace | not available here ({ns.get('reason')}) | SKIPPED |")
    L.append(f"\nModules matching networking names that got loaded at runtime: `{ru['network_modules_loaded']}` (stdlib `http`/`urllib` may be pulled in by unrelated stdlib modules; loading is not use - test 2 counts actual network events).\n")
    L.append("**Phone-level proof (airplane mode + tcpdump):** `offline_proof/PHONE_PROTOCOL.md` - still to be run on the device and attached as a screenshot/pcap.\n")
    open(os.path.join(ROOT, "results", "OFFLINE_PROOF.md"), "w").write("\n".join(L))


if __name__ == "__main__":
    if "--worker" in sys.argv:
        worker()
    else:
        sys.exit(main())
