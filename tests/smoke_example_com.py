"""Smoke test: launch Firefox, navigate to example.com, read the title, shut down cleanly.

Runs inside the hardened browser container. A plain script (pytest is not in the image).
Only headless=True and a fixed timezone are passed to the launcher; nothing else is configured.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path

import psutil

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_PREFIX = os.environ.get("SMOKE_LOG_PREFIX", "")
# Strict mode (container with an init): zombies count as leftovers too.
STRICT_PROCESSES = os.environ.get("SMOKE_STRICT_PROCESSES") == "1"
TARGET = "https://example.com"
EXPECTED_TITLE = "Example Domain"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / f"{LOG_PREFIX}smoke-python.log", mode="w"),
    ],
)
# Every outbound HTTP connection the Python side opens (requests/urllib3).
logging.getLogger("urllib3").setLevel(logging.DEBUG)
log = logging.getLogger("smoke")


def browser_processes() -> list[dict]:
    """Firefox / Xvfb processes still present, with state and role.

    status "zombie" means the process has exited but nobody reaped it, which
    happens when this script is PID 1 in a container without an init.
    """
    out = []
    for p in psutil.process_iter(["pid", "ppid", "name", "status", "cmdline"]):
        name = (p.info["name"] or "").lower()
        if any(k in name for k in ("firefox", "xvfb", "crashhelper")):
            # Role only (e.g. "--backgroundtask pingsender"); never URLs, paths or IDs.
            args = [a for a in (p.info["cmdline"] or [])[1:3] if a.startswith("-") or a.isalpha()]
            out.append({"pid": p.info["pid"], "ppid": p.info["ppid"], "name": p.info["name"],
                        "status": p.info["status"], "role": " ".join(args)})
    return out


def runtime_context() -> dict:
    """The process's security context, as recorded evidence."""
    ctx = {"uid": os.getuid(), "gid": os.getgid()}
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            key = line.split(":", 1)[0]
            if key in ("CapEff", "CapPrm", "CapBnd", "NoNewPrivs", "Seccomp"):
                ctx[key] = line.split(":", 1)[1].strip()
        ctx["pid1"] = Path("/proc/1/comm").read_text().strip()
    except OSError as exc:
        ctx["error"] = str(exc)
    return ctx


def profile_dirs() -> list[str]:
    return sorted(glob.glob(os.path.join(tempfile.gettempdir(), "invisible_profile_*")))


def wait_for_exit(max_seconds: float = 30.0) -> tuple[list[dict], list[dict]]:
    """Poll until no live (non-zombie) browser process remains.

    Returns (first snapshot right after close, final snapshot).
    """
    first = browser_processes()
    deadline = time.monotonic() + max_seconds
    final = first
    while time.monotonic() < deadline:
        final = browser_processes()
        if not [p for p in final if p["status"] != psutil.STATUS_ZOMBIE]:
            break
        time.sleep(1)
    return first, final


def main() -> int:
    from invisible_playwright import InvisiblePlaywright

    result: dict = {"target": TARGET, "steps": {}, "ok": False,
                    "runtime_context": runtime_context(),
                    "strict_processes": STRICT_PROCESSES,
                    "profiles_before": profile_dirs()}
    t0 = time.monotonic()

    def step(name: str, start: float, **extra) -> None:
        result["steps"][name] = {"seconds": round(time.monotonic() - start, 2), **extra}
        log.info("STEP %s ok (%.2fs) %s", name, time.monotonic() - start, extra or "")

    try:
        sf = InvisiblePlaywright(headless=True, timezone="UTC")
        s = time.monotonic()
        with sf as browser:
            step("launch", s, browser_version=browser.version)

            s = time.monotonic()
            page = browser.new_page()
            step("new_page", s)

            s = time.monotonic()
            resp = page.goto(TARGET, wait_until="load", timeout=90_000)
            step("goto", s, status=resp.status if resp else None, url=page.url)

            s = time.monotonic()
            title = page.title()
            step("title", s, title=title)
            assert title == EXPECTED_TITLE, f"unexpected title {title!r}"

            s = time.monotonic()
        step("close", s)

        s = time.monotonic()
        first, final = wait_for_exit()
        live = [p for p in final if p["status"] != psutil.STATUS_ZOMBIE]
        result["processes_right_after_close"] = first
        result["processes_after_wait"] = final
        step("post_close_wait", s, live_remaining=len(live),
             zombies_remaining=len(final) - len(live))
        for p in first:
            log.info("post-close process: %s", p)
        assert not live, f"live browser processes left after shutdown: {live}"
        if STRICT_PROCESSES:
            assert not final, f"browser processes (incl. zombies) left after shutdown: {final}"

        leftover_profiles = [p for p in profile_dirs() if p not in result["profiles_before"]]
        result["profiles_after"] = leftover_profiles
        log.info("temporary profiles left after close: %s", leftover_profiles or "none")
        assert not leftover_profiles, f"temporary profile not removed: {leftover_profiles}"
        result["ok"] = True
    except Exception as exc:  # report, do not retry
        log.exception("smoke test FAILED")
        result["error"] = f"{type(exc).__name__}: {exc}"
        result.setdefault("processes_after_wait", browser_processes())
    finally:
        result["total_seconds"] = round(time.monotonic() - t0, 2)
        (LOG_DIR / f"{LOG_PREFIX}smoke-result.json").write_text(json.dumps(result, indent=2))
        log.info("RESULT %s", json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
