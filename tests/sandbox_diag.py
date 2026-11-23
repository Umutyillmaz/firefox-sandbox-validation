"""Firefox's own sandbox state, per process, under the hardened container config.

Read-only. It opens example.com (approved) to get a web-content process, reads the
sandbox prefs from the live profile, reads /proc for every Firefox process (compared
with this Python process's own baseline), and collects Firefox's own sandbox log lines.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import psutil
from invisible_playwright import InvisiblePlaywright

OUT = Path(__file__).resolve().parent.parent / "logs" / os.environ.get("SANDBOX_DIAG_NAME", "sandbox-diag.json")
FIELDS = ("Seccomp", "Seccomp_filters", "NoNewPrivs", "CapEff")


def status(pid) -> dict:
    out = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        k, _, v = line.partition(":")
        if k in FIELDS:
            out[k] = v.strip()
    return out


def ns(pid, kind: str) -> str:
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError as exc:
        return f"unreadable: {exc.strerror}"


report: dict = {"python_baseline": {**status("self"), **{f"{k}_ns": ns("self", k) for k in ("user", "pid", "net")}}}

with InvisiblePlaywright(headless=True, timezone="UTC") as browser:
    page = browser.new_page()
    page.goto("https://example.com", wait_until="load", timeout=90_000)

    # 1. Sandbox prefs in the live profile's pref files only. The HTTP cache and
    #    other profile data are deliberately not read (they can hold page content).
    prefs = {}
    profiles = glob.glob(os.path.join(tempfile.gettempdir(), "invisible_profile_*"))
    report["profile_count"] = len(profiles)
    for prof in profiles:
        for name in ("user.js", "prefs.js"):
            p = Path(prof) / name
            if p.is_file():
                for line in p.read_text(errors="replace").splitlines():
                    if "security.sandbox" in line:
                        prefs.setdefault(name, []).append(line.strip()[:200])
    report["sandbox_prefs_in_profile"] = prefs

    # 2. Per-process state.
    procs = []
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        cmd = p.info["cmdline"] or []
        if not cmd or "firefox" not in cmd[0]:
            continue
        procs.append({"pid": p.pid, "comm": p.info["name"],
                      "child_type": next((a for a in cmd if a in ("tab", "socket", "rdd", "utility", "gpu")), None),
                      **status(p.pid), **{f"{k}_ns": ns(p.pid, k) for k in ("user", "pid", "net")}})
    report["firefox_processes"] = procs

    # 3. Firefox's own words. The launcher keeps the browser's stdout/stderr in memory
    #    (last 200 lines); about:support is not readable through the automation driver.
    #    Read it in-process, read-only, and keep only sandbox-related lines.
    import gc
    outputs = [o for o in gc.get_objects() if type(o).__name__ == "ProcessOutput"]
    lines = []
    for o in outputs:
        with o._cv:
            lines.extend(list(o._lines))
    report["engine_output_buffers"] = len(outputs)
    report["engine_output_lines"] = len(lines)
    report["engine_output_sandbox_lines"] = [l for l in lines if re.search(r"sandbox|seccomp|namespace", l, re.I)]

OUT.write_text(json.dumps(report, indent=2))
summary = {k: v for k, v in report.items() if k != "firefox_processes"}
summary["firefox_processes"] = [f'{p["comm"]}: filters={p["Seccomp_filters"]} userns_same={p["user_ns"] == report["python_baseline"]["user_ns"]}'
                                 for p in report["firefox_processes"]]
print(json.dumps(summary, indent=2))
sys.exit(0)
