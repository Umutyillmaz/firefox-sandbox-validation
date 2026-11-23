"""Egress-policy validation. Runs inside the hardened browser container.

It uses only harmless destinations: IANA example domains, public DNS resolvers
(no payload beyond a single DNS question), and background-service hostnames a
default Firefox/launcher setup contacts (resolved only, never contacted). Each check states its expectation;
the script exits non-zero if any check deviates.

Environment:
  PROBE_UNAPPROVED_IP  IPv4 of an unapproved web host, resolved on the host (example.org)
  PROBE_UPSTREAM_DNS   the Docker resolver that only dnsmasq may use
"""
from __future__ import annotations

import errno
import json
import os
import socket
import ssl
import struct
import sys
import urllib.request
from pathlib import Path

LOG = Path(__file__).resolve().parent.parent / "logs" / "egress-probe.json"
UNAPPROVED_IP = os.environ["PROBE_UNAPPROVED_IP"]   # set by scripts/run_validation.sh
UPSTREAM_DNS = os.environ["PROBE_UPSTREAM_DNS"]     # set by scripts/run_validation.sh
TIMEOUT = 5.0

results: list[dict] = []


def record(check: str, expect: str, ok: bool, detail: str) -> None:
    results.append({"check": check, "expect": expect, "pass": ok, "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {check:58s} expect={expect:8s} {detail}")


def resolve(name: str) -> tuple[bool, str]:
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)})
        return True, ",".join(addrs)
    except socket.gaierror as exc:
        return False, f"gaierror {exc.errno}: {exc.strerror}"


def tcp_connect(host: str, port: int, family=socket.AF_INET) -> tuple[bool, str]:
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((host, port))
        return True, "connected"
    except OSError as exc:
        return False, f"{type(exc).__name__} {errno.errorcode.get(exc.errno, exc.errno)}"
    finally:
        s.close()


def dns_query_bytes(name: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def udp_dns(server: str, name: str) -> tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((server, 53))
        s.send(dns_query_bytes(name))
        data = s.recv(512)
        return True, f"answer {len(data)} bytes"
    except OSError as exc:
        return False, f"{type(exc).__name__} {errno.errorcode.get(exc.errno, exc.errno) if exc.errno else 'timeout'}"
    finally:
        s.close()


def udp_send(host: str, port: int) -> tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.connect((host, port))
        s.send(b"\x00" * 32)
        s.recv(64)
        return True, "got a reply"
    except OSError as exc:
        return False, f"{type(exc).__name__} {errno.errorcode.get(exc.errno, exc.errno) if exc.errno else 'timeout'}"
    finally:
        s.close()


def https_get(url: str) -> tuple[bool, str]:
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, timeout=15, context=ctx) as r:
            return r.status == 200, f"HTTP {r.status}, TLS verified"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    # --- Runtime context -----------------------------------------------------
    status = {l.split(":")[0]: l.split(":", 1)[1].strip()
              for l in Path("/proc/self/status").read_text().splitlines()
              if l.split(":")[0] in ("CapEff", "NoNewPrivs", "Seccomp")}
    record("runtime: non-root uid", "uid!=0", os.getuid() != 0, f"uid={os.getuid()}")
    record("runtime: no effective capabilities (cannot alter nft)", "CapEff=0",
           int(status["CapEff"], 16) == 0, f"CapEff={status['CapEff']}")
    record("runtime: no_new_privs set", "1", status["NoNewPrivs"] == "1", f"NoNewPrivs={status['NoNewPrivs']}")
    record("runtime: seccomp filter active", "2", status["Seccomp"] == "2", f"Seccomp={status['Seccomp']}")
    record("runtime: PID 1 is an init", "init", Path("/proc/1/comm").read_text().strip() in ("tini", "docker-init"),
           f"pid1={Path('/proc/1/comm').read_text().strip()}")
    resolv = Path("/etc/resolv.conf").read_text()
    record("runtime: resolv.conf points at filtering resolver", "127.0.0.1",
           "nameserver 127.0.0.1" in resolv and UPSTREAM_DNS not in resolv,
           " ".join(l for l in resolv.splitlines() if l.startswith("nameserver")))

    # --- Filesystem ----------------------------------------------------------
    for path in ("/app/tests/_probe_write", "/_probe_write", "/root/.cache/invisible-playwright/_probe_write"):
        try:
            Path(path).write_text("x")
            Path(path).unlink()
            record(f"fs: write {path}", "denied", False, "write succeeded")
        except OSError as exc:
            record(f"fs: write {path}", "denied", True, errno.errorcode.get(exc.errno, str(exc.errno)))
    try:
        Path("/tmp/_probe_write").write_text("x"); Path("/tmp/_probe_write").unlink()
        record("fs: write /tmp (tmpfs)", "allowed", True, "ok")
    except OSError as exc:
        record("fs: write /tmp (tmpfs)", "allowed", False, str(exc))

    # --- DNS policy ----------------------------------------------------------
    ok, d = resolve("example.com")
    record("dns: example.com (approved)", "resolves", ok, d)
    ok, d = resolve("firefox.settings.services.mozilla.com")
    record("dns: firefox.settings.services.mozilla.com (approved)", "resolves", ok, d)
    for name in ("example.org", "example.net",                           # IANA test domains
                 "github.com", "api.github.com",                         # launcher usage counter / GeoIP
                 "api.ipify.org", "icanhazip.com", "checkip.amazonaws.com",
                 "incoming.telemetry.mozilla.org", "ads.mozilla.org",    # Mozilla telemetry / ads
                 "location.services.mozilla.com", "normandy.cdn.mozilla.net",
                 "merino.services.mozilla.com", "mozilla.cloudflare-dns.com"):
        ok, d = resolve(name)
        record(f"dns: {name}", "NXDOMAIN", not ok, d)

    # --- Approved traffic ----------------------------------------------------
    ok, d = https_get("https://example.com/")
    record("https: GET https://example.com/", "200", ok, d)
    ok, d = https_get("https://firefox.settings.services.mozilla.com/v2/")
    record("https: GET Remote Settings server info", "200", ok, d)

    # --- Bypass attempts (must all fail) ------------------------------------
    ok, d = tcp_connect(UNAPPROVED_IP, 443)
    record(f"tcp: direct IP {UNAPPROVED_IP}:443 (example.org, no DNS)", "blocked", not ok, d)
    ok, d = tcp_connect(resolve("example.com")[1].split(",")[0], 80)
    record("tcp: approved host on port 80", "blocked", not ok, d)
    ok, d = tcp_connect("1.1.1.1", 443)
    record("tcp: 1.1.1.1:443 (DNS-over-HTTPS bypass)", "blocked", not ok, d)
    ok, d = tcp_connect("1.1.1.1", 853)
    record("tcp: 1.1.1.1:853 (DNS-over-TLS bypass)", "blocked", not ok, d)
    ok, d = udp_dns("8.8.8.8", "example.org")
    record("udp: 8.8.8.8:53 (external DNS bypass)", "blocked", not ok, d)
    ok, d = udp_dns(UPSTREAM_DNS, "example.org")
    record(f"udp: {UPSTREAM_DNS}:53 (upstream resolver, non-dnsmasq uid)", "blocked", not ok, d)
    ok, d = udp_send(resolve("example.com")[1].split(",")[0], 443)
    record("udp: approved host on 443 (QUIC)", "blocked", not ok, d)
    ok, d = tcp_connect("2606:4700:4700::1111", 443, socket.AF_INET6)
    record("tcp6: [2606:4700:4700::1111]:443 (IPv6)", "blocked", not ok, d)

    LOG.write_text(json.dumps(results, indent=2))
    failed = [r for r in results if not r["pass"]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
