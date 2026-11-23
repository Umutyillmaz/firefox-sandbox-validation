"""Build the uploadable evidence artifact from the raw evidence directory.

    python3 scripts/sanitize_evidence.py logs/run/evidence logs/artifact

Allowlist design: the artifact is CONSTRUCTED field by field from what the
acceptance verdict needs. Nothing raw is copied: no build logs, no browser
stdout, no raw docker inspect or compose config (absolute paths, container IPs,
env), no profile paths, no telemetry URLs or IDs, no launcher seed.

Then:
  - the upstream DNS address and RFC 1918 / link-local / CGNAT IPv4 addresses are redacted;
  - a leak scan refuses (exit 3) if anything token-, cookie-, key-, profile- or
    home-path-shaped remains. The workflow uploads nothing when this step fails.

A missing or partial evidence directory still produces an artifact
(status.json says what is missing), so a failed run is diagnosable.
Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

PRIVATE_V4 = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|169\.254|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d{1,3}\.\d{1,3}\b")
LEAK_PATTERNS = {
    "github token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "bearer/authorization": re.compile(r"(?i)\b(?:authorization|bearer)\s*[:=]"),
    "cookie": re.compile(r"(?i)\b(?:set-)?cookie\s*[:=]"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "browser profile path": re.compile(r"invisible_profile_"),
    "runner/home path": re.compile(r"/home/[a-z_][a-z0-9_-]*/|/Users/[^/\s]+/"),
    "actions runtime token": re.compile(r"ACTIONS_(?:RUNTIME|ID_TOKEN)"),
    "private IPv4 (unredacted)": PRIVATE_V4,
}


def read_json(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def main(src: Path, dst: Path) -> int:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    out: dict[str, object] = {}
    missing: list[str] = []

    def need(name: str):
        v = read_json(src / name)
        if v is None:
            missing.append(name)
        return v

    # verdict + checks (the acceptance output is already a summary)
    acc = need("acceptance.json")
    if acc is not None:
        out["verdict.json"] = acc

    host = need("host.json")
    if host is not None:
        out["host.json"] = {k: host.get(k) for k in ("machine", "system", "kernel", "cpu", "virt", "disk_free_gb",
                                                     "docker_arch", "docker_version", "docker_os",
                                                     "docker_security_options")}

    prim = need("primitives.json")
    if prim is not None:
        out["primitives.json"] = prim  # kernel facts and errno values only

    diag = need("sandbox-diag.json")
    if diag is not None:
        keep = ("comm", "child_type", "Seccomp", "Seccomp_filters", "NoNewPrivs", "CapEff", "user_ns", "pid_ns", "net_ns")
        out["sandbox-diag.json"] = {
            "python_baseline": diag.get("python_baseline"),
            "firefox_processes": [{k: p.get(k) for k in keep} for p in diag.get("firefox_processes", [])],
            "sandbox_prefs_in_profile": diag.get("sandbox_prefs_in_profile"),
            "engine_output_sandbox_lines": diag.get("engine_output_sandbox_lines"),
        }

    probe = need("egress-probe.json")
    if probe is not None:
        out["egress-probe.json"] = probe

    smoke = need("smoke-result.json")
    if smoke is not None:
        procs = lambda key: [{"comm": p.get("name"), "status": p.get("status")} for p in smoke.get(key) or []]
        out["smoke-result.json"] = {
            "ok": smoke.get("ok"), "error": smoke.get("error"), "target": smoke.get("target"),
            "steps": {k: {kk: vv for kk, vv in v.items() if kk != "seed"} for k, v in (smoke.get("steps") or {}).items()},
            "runtime_context": smoke.get("runtime_context"), "strict_processes": smoke.get("strict_processes"),
            "processes_right_after_close": procs("processes_right_after_close"),
            "processes_after_wait": procs("processes_after_wait"),
            "profiles_left_after_close": len(smoke.get("profiles_after") or []),
            "total_seconds": smoke.get("total_seconds"),
        }

    cfg, egr = need("compose-config.json"), need("egress-inspect.json")
    if cfg is not None:
        sec = {}
        for svc in ("browser", "egress"):
            s = cfg.get("services", {}).get(svc, {})
            sec[svc] = {k: s.get(k) for k in ("image", "platform", "privileged", "user", "init", "read_only", "cap_drop",
                                              "cap_add", "security_opt", "pids_limit", "mem_limit", "cpus", "network_mode")}
        if egr:
            hc = egr[0].get("HostConfig", {})
            sec["egress_runtime"] = {k: hc.get(k) for k in ("Privileged", "CapAdd", "CapDrop", "SecurityOpt", "ReadonlyRootfs")}
        out["docker-security.json"] = sec

    # egress evidence: derived counts, never the raw dnsmasq log
    dns = src / "dnsmasq-smoke.log"
    rules = src / "ruleset-after-smoke.txt"
    if dns.is_file() and rules.is_file():
        text = dns.read_text(errors="replace")
        fwd = Counter(re.findall(r"forwarded (\S+) to", text))
        nx = Counter(re.findall(r"config (\S+) is NXDOMAIN", text))
        rt = rules.read_text(errors="replace")
        counters = {m.group(1): int(m.group(2)) for m in re.finditer(r"counter (\w+) \{\s*packets (\d+)", rt)}

        def set_elems(name: str) -> list[str]:
            m = re.search(r"set %s \{.*?(?:elements = \{([^}]*)\})?\s*\}" % name, rt, re.S)
            return [e.strip() for e in (m.group(1) or "").replace("\n", " ").split(",") if e.strip()] if m else []
        out["egress-summary.json"] = {
            "dns_forwarded_upstream": dict(fwd), "dns_refused_nxdomain": dict(nx),
            "nft_counters_packets": counters, "nft_allowed4_count": len(set_elems("allowed4")),
            "nft_rejected4": set_elems("rejected4"), "nft_rejected6": set_elems("rejected6"),
        }
    else:
        missing += [p.name for p in (dns, rules) if not p.is_file()]

    ev = src / "engine-version.txt"
    if ev.is_file():
        out["engine-version.txt"] = "\n".join(l for l in ev.read_text().splitlines()
                                              if l.split(" ")[0] in ("invisible_playwright", "invisible_core", "engine", "seal")
                                              and "/" not in l) + "\n"
    else:
        missing.append("engine-version.txt")

    out["status.json"] = {"evidence_dir_present": src.is_dir(), "missing_inputs": sorted(set(missing)),
                          "note": "Sanitized: allowlisted fields only; upstream DNS and private IPv4 redacted."}

    # serialize + redact
    upstream = (src / "upstream-dns.txt").read_text().strip() if (src / "upstream-dns.txt").is_file() else None
    for name, val in out.items():
        text = val if isinstance(val, str) else json.dumps(val, indent=2, default=str)
        if upstream:
            text = re.sub(r"(?<![\d.])" + re.escape(upstream) + r"(?![\d.])", "<upstream-dns>", text)
        text = PRIVATE_V4.sub("<private-ip>", text)
        (dst / name).write_text(text)

    # leak scan over everything that would be uploaded
    hits = []
    for p in sorted(dst.iterdir()):
        t = p.read_text(errors="replace")
        hits += [f"{p.name}: {label}" for label, rx in LEAK_PATTERNS.items() if rx.search(t)]
    if hits:
        shutil.rmtree(dst)
        print("LEAK SCAN FAILED, artifact removed, nothing will be uploaded:\n  " + "\n  ".join(hits), file=sys.stderr)
        return 3

    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(dst.iterdir()))
    (dst / "SHA256SUMS").write_text(sums)
    for p in dst.iterdir():
        p.chmod(0o644)
    print(f"sanitized artifact: {dst} ({len(out)} files); missing inputs: {status if (status := sorted(set(missing))) else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
