"""Acceptance: classify the native-host evidence as FULL, PARTIAL or FAIL.

Runs on the host with the Python standard library only:
    python3 tests/acceptance.py logs/run/evidence

Expected files in the evidence directory (written by scripts/run_validation.sh):
    host.json, compose-config.json, egress-inspect.json, primitives.json,
    egress-probe.json, sandbox-diag.json, smoke-result.json

Rules:
  - a browser that runs proves nothing about the sandbox;
  - Firefox's seccomp layer is proven only by content processes carrying MORE
    seccomp filters than the container's own Python baseline;
  - namespace isolation is assessed separately: seccomp without namespaces is
    PARTIAL, never FULL;
  - any weakened Docker protection, failed egress check, failed smoke test,
    or non-native host is FAIL.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CONTENT = {"Web Content", "Isolated Web Co", "Privileged Cont", "WebExtensions", "file:// Content"}
OTHER_SANDBOXED = {"Socket Process", "RDD Process", "Utility Process"}
EGRESS_CAPS_ALLOWED = {"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_SETUID", "CAP_SETGID",
                       "NET_ADMIN", "NET_BIND_SERVICE", "SETUID", "SETGID"}

checks: list[tuple[str, str, bool, str]] = []  # (group, name, ok, detail)


def check(group: str, name: str, ok: bool, detail: str = "") -> bool:
    checks.append((group, name, bool(ok), detail))
    return bool(ok)


def load(d: Path, name: str):
    p = d / name
    if not p.is_file():
        check("evidence", f"{name} present", False, "missing")
        return None
    return json.loads(p.read_text())


def main(d: Path) -> int:
    host = load(d, "host.json")
    prim = load(d, "primitives.json")
    diag = load(d, "sandbox-diag.json")
    probe = load(d, "egress-probe.json")
    smoke = load(d, "smoke-result.json")
    cfg = load(d, "compose-config.json")
    egr = load(d, "egress-inspect.json")

    # 1. Native host
    if host:
        check("host", "uname -m is x86_64", host.get("machine") == "x86_64", host.get("machine"))
        check("host", "Linux kernel", host.get("system") == "Linux", host.get("kernel"))
        check("host", "not QEMU/TCG emulation", host.get("virt") != "qemu", f"virt={host.get('virt')}")
        check("host", "Docker server is x86_64", host.get("docker_arch") == "x86_64", host.get("docker_arch"))
        sec = " ".join(host.get("docker_security_options", []))
        check("docker", "Docker builtin/default seccomp profile active", "name=seccomp" in sec and "unconfined" not in sec, sec)
    if prim:
        check("host", "no binary translator in container process", prim.get("emulator") == "none (native)", prim.get("emulator"))

    # 2. Docker protections not weakened (configuration + runtime)
    if cfg:
        b = cfg["services"]["browser"]
        e = cfg["services"]["egress"]
        check("docker", "browser: not privileged", not b.get("privileged", False))
        check("docker", "browser: cap_drop ALL, no cap_add", "ALL" in (b.get("cap_drop") or []) and not b.get("cap_add"),
              f"drop={b.get('cap_drop')} add={b.get('cap_add')}")
        so = b.get("security_opt") or []
        check("docker", "browser: no-new-privileges, seccomp not unconfined",
              any("no-new-privileges" in s for s in so) and not any("unconfined" in s for s in so), str(so))
        check("docker", "browser: read-only rootfs, init, non-root user",
              b.get("read_only") is True and b.get("init") is True and str(b.get("user", "")).startswith("10001"),
              f"read_only={b.get('read_only')} init={b.get('init')} user={b.get('user')}")
        check("docker", "egress: not privileged, only the 4 expected caps",
              not e.get("privileged", False) and set(e.get("cap_add") or []) <= EGRESS_CAPS_ALLOWED,
              f"add={e.get('cap_add')}")
    if egr:
        hc = egr[0]["HostConfig"]
        check("docker", "egress (runtime): Privileged=false, no seccomp=unconfined",
              hc.get("Privileged") is False and not any("unconfined" in s for s in (hc.get("SecurityOpt") or [])),
              f"SecurityOpt={hc.get('SecurityOpt')} CapAdd={hc.get('CapAdd')}")

    # 3. Primitives: does this host let a container process install seccomp filters?
    base_filters = None
    if prim:
        self_ = prim.get("self", {})
        base_filters = int(self_.get("Seccomp_filters", "0") or 0)
        check("baseline", "container baseline: Seccomp=2, filters>=1, NoNewPrivs=1, CapEff=0",
              self_.get("Seccomp") == "2" and base_filters >= 1 and self_.get("NoNewPrivs") == "1"
              and int(self_.get("CapEff", "1"), 16) == 0, str(self_))
        k1 = prim.get("probe_kHasSeccompBPF (prctl NULL, want EFAULT)", {}).get("errno")
        k2 = prim.get("probe_kHasSeccompTSync (seccomp TSYNC NULL, want EFAULT)", {}).get("errno")
        inst = prim.get("install_allow_all_filter", {})
        check("primitives", "kHasSeccompBPF probe -> EFAULT", k1 == "EFAULT", str(k1))
        check("primitives", "kHasSeccompTSync probe -> EFAULT", k2 == "EFAULT", str(k2))
        check("primitives", "allow-all filter installs (filters +1)",
              inst.get("install", {}).get("rv") == 0 and int(inst.get("filters_after", 0)) == int(inst.get("filters_before", 0)) + 1,
              f"{inst.get('filters_before')}->{inst.get('filters_after')} {inst.get('install')}")

    # 4. Firefox's own seccomp layer, per process, against the baseline
    ns_layer = False
    if diag:
        pb = diag["python_baseline"]
        base = int(pb["Seccomp_filters"])
        if base_filters is not None:
            check("baseline", "diag baseline equals primitives baseline", base == base_filters, f"{base} vs {base_filters}")
        procs = diag.get("firefox_processes", [])
        content = [p for p in procs if p["comm"] in CONTENT]
        check("firefox-seccomp", "at least one web-content process observed",
              any(p["comm"] in ("Web Content", "Isolated Web Co") for p in content),
              ", ".join(sorted({p["comm"] for p in procs})))
        for p in content:
            check("firefox-seccomp", f"{p['comm']} (pid {p['pid']}) filters > baseline",
                  int(p["Seccomp_filters"]) > base, f"{p['Seccomp_filters']} vs baseline {base}")
        for p in procs:
            if p["comm"] in OTHER_SANDBOXED:
                # Reported, not gating: expected +1 on a native host.
                checks.append(("info", f"{p['comm']} (pid {p['pid']}) filters", True,
                               f"{p['Seccomp_filters']} vs baseline {base} ({'ABOVE' if int(p['Seccomp_filters']) > base else 'at baseline'})"))
        # Namespaces: separate assessment
        ns_layer = bool(content) and all(p["user_ns"] != pb["user_ns"] and p["pid_ns"] != pb["pid_ns"] for p in content)
        userns_fail_logged = any("CanCreateUserNamespace" in l for l in diag.get("engine_output_sandbox_lines", []))
        checks.append(("namespaces", "content processes in own user+pid namespaces", True,
                       f"{'YES' if ns_layer else 'NO'}; engine logged CanCreateUserNamespace failure: {userns_fail_logged}"))

    # 5. Egress isolation
    if probe:
        failed = [r["check"] for r in probe if not r["pass"]]
        check("egress", f"egress probe {len(probe) - len(failed)}/{len(probe)}", not failed, "; ".join(failed))
    # 6. Functional + cleanup
    if smoke:
        st = smoke.get("steps", {})
        check("smoke", "smoke ok (launch, goto 200, title, close)", smoke.get("ok") is True
              and st.get("goto", {}).get("status") == 200 and st.get("title", {}).get("title") == "Example Domain",
              smoke.get("error", ""))
        check("smoke", "strict cleanup: 0 live, 0 zombie, no profile left",
              smoke.get("strict_processes") is True and not smoke.get("processes_after_wait")
              and smoke.get("profiles_after") == [], "")

    gating = [c for c in checks if c[0] not in ("info", "namespaces")]
    ok = all(c[2] for c in gating) and bool(gating)
    verdict = ("FAIL" if not ok else ("PASS-FULL" if ns_layer else "PASS-PARTIAL (seccomp layer active, namespace layer absent)"))
    for g, n, good, det in checks:
        mark = "info" if g in ("info", "namespaces") else ("PASS" if good else "FAIL")
        print(f"[{mark:4s}] {g:16s} {n:58s} {det}")
    print(f"\nVERDICT: {verdict}")
    (d / "acceptance.json").write_text(json.dumps({"verdict": verdict, "checks": checks}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "logs/run/evidence")))
