"""The kernel primitives Firefox's Linux sandbox depends on.

Each probe runs in a forked child, so the parent process stays unchanged.
Nothing here weakens isolation. The only filter installed is an allow-all
filter in a child that exits right afterwards, which can only add restrictions.

The probes mirror Firefox's own startup tests (security/sandbox/linux/SandboxInfo.cpp):
  kHasSeccompBPF   prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL)        -> -1/EFAULT if supported
  kHasSeccompTSync seccomp(SECCOMP_SET_MODE_FILTER, TSYNC, NULL)           -> -1/EFAULT if supported
  kHasUserNamespaces / kHasPrivilegedUserNamespaces: unshare(CLONE_NEWUSER [| NEWPID | NEWNET])
Then a real install of an allow-all filter, and a read of Seccomp_filters afterwards.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
import platform
import sys
from pathlib import Path

PR_GET_SECCOMP, PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS = 21, 22, 38
SECCOMP_MODE_FILTER = 2
SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC = 1, 1
NR_SECCOMP = {"x86_64": 317, "aarch64": 277}[platform.machine()]
SECCOMP_RET_ALLOW = 0x7FFF0000
BPF_RET_K = 0x06

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
libc.syscall.restype = ctypes.c_long


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def status(field: str) -> str:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(field + ":"):
            return line.split(":", 1)[1].strip()
    return "?"


def ret(rv: int) -> dict:
    e = ctypes.get_errno()
    return {"rv": rv, "errno": errno.errorcode.get(e, e) if rv == -1 else None}


def in_child(fn) -> dict:
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            out = fn()
        except Exception as exc:  # noqa: BLE001
            out = {"exception": f"{type(exc).__name__}: {exc}"}
        os.write(w, json.dumps(out).encode())
        os._exit(0)
    os.close(w)
    data = b""
    while chunk := os.read(r, 65536):
        data += chunk
    _, st = os.waitpid(pid, 0)
    res = json.loads(data) if data else {}
    if os.WIFSIGNALED(st):
        res["child_killed_by_signal"] = os.WTERMSIG(st)
    return res


def probe_prctl_null() -> dict:
    return ret(libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, None, 0, 0))


def probe_tsync_null() -> dict:
    return ret(libc.syscall(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, None))


def probe_install_allow_all() -> dict:
    before = status("Seccomp_filters")
    nnp = ret(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, None, 0, 0))
    prog_arr = (SockFilter * 1)(SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    prog = SockFprog(1, prog_arr)
    inst = ret(libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0))
    return {"filters_before": before, "no_new_privs": nnp, "install": inst,
            "filters_after": status("Seccomp_filters"), "Seccomp_after": status("Seccomp")}


def probe_unshare(flags: int) -> dict:
    try:
        os.unshare(flags)
        return {"rv": 0, "errno": None}
    except OSError as exc:
        return {"rv": -1, "errno": errno.errorcode.get(exc.errno, exc.errno)}


def main() -> None:
    maps = Path("/proc/self/maps").read_text()
    result = {
        "machine": platform.machine(),
        "emulator": "rosetta" if "[rosetta]" in maps else ("qemu" if "qemu" in maps else "none (native)"),
        "uid": os.getuid(),
        "self": {k: status(k) for k in ("Seccomp", "Seccomp_filters", "NoNewPrivs", "CapEff")},
        "kernel_seccomp_actions": Path("/proc/sys/kernel/seccomp/actions_avail").read_text().strip(),
        "max_user_namespaces": Path("/proc/sys/user/max_user_namespaces").read_text().strip(),
        "probe_kHasSeccompBPF (prctl NULL, want EFAULT)": in_child(probe_prctl_null),
        "probe_kHasSeccompTSync (seccomp TSYNC NULL, want EFAULT)": in_child(probe_tsync_null),
        "install_allow_all_filter": in_child(probe_install_allow_all),
        "unshare_NEWUSER": in_child(lambda: probe_unshare(os.CLONE_NEWUSER)),
        "unshare_NEWUSER|NEWPID|NEWNET": in_child(
            lambda: probe_unshare(os.CLONE_NEWUSER | os.CLONE_NEWPID | os.CLONE_NEWNET)),
    }
    print(json.dumps(result, indent=2))
    out = os.environ.get("PRIMITIVES_OUT")
    if out:
        Path(out).write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    sys.exit(main())
