# firefox-sandbox-validation

Checks whether a packaged Firefox build actually enables **Firefox's own Linux
content sandbox** (seccomp-bpf, plus namespaces where available) when it runs
inside a hardened Docker container on a native x86_64 Linux host.

The build under test is the Firefox engine shipped with the
[`invisible-playwright`](https://pypi.org/project/invisible-playwright/) package
(pinned to 0.58.0 / Firefox 159.0, sha256-verified). The harness only launches it
headless, opens `https://example.com`, and inspects process security state.

## What a run does
1. **Preflight:** refuses anything except native x86_64 Linux with Docker's
   default seccomp profile (no Rosetta, no QEMU/TCG).
2. **Build:** digest-pinned images; `pip --require-hashes`; the Firefox archive
   is checked against its sha256 seal.
3. **Kernel primitives** (`tests/seccomp_primitives.py`): can a container process
   install seccomp filters and create user namespaces?
4. **Egress policy** (`tests/egress_probe.py`): a sidecar allows only
   `example.com` and Mozilla Remote Settings (certificate revocation data), on
   TCP 443. Everything else gets NXDOMAIN or is rejected.
5. **Firefox sandbox** (`tests/sandbox_diag.py`): seccomp filter count and
   namespaces of every Firefox process, compared with the container's own
   baseline, plus Firefox's own sandbox log lines.
6. **Smoke test** (`tests/smoke_example_com.py`): launch, HTTP 200, title,
   clean shutdown, no leftover processes or profiles.
7. **Verdict** (`tests/acceptance.py`), reported by `scripts/ci_summary.py`.

| Verdict | Meaning |
|---|---|
| `PASS-FULL` | Content processes have Firefox's own seccomp filter **and** their own namespaces |
| `PASS-PARTIAL` | Firefox's seccomp layer is active, the namespace layer is absent (expected under Docker's default seccomp profile) |
| `FAIL` | Any content process at the baseline, any weakened container setting, or a failed egress, smoke or cleanup check |
| `ERROR` | No verdict (preflight, build or timeout) |

A browser that launches is never a pass by itself.

## Container hardening
- **Browser container:** non-root (uid 10001), `cap_drop: ALL`,
  `no-new-privileges`, Docker's default seccomp profile, read-only root
  filesystem, tmpfs for profiles, init process, pids/memory/CPU limits, no
  core dumps.
- **Egress sidecar:** holds only `NET_ADMIN`, `NET_BIND_SERVICE`, `SETUID` and
  `SETGID`.
- **Never used:** privileged containers or seccomp changes.

## Running
- **GitHub Actions:** `.github/workflows/sandbox-validation.yml`, started
  manually only (`workflow_dispatch`).
  - Standard `ubuntu-24.04` runner, read-only token, no secrets.
  - Only GitHub-owned actions, pinned by SHA.
  - Sanitized evidence is kept as an artifact for 1 day.
- **Locally**, on a native x86_64 Linux host with Docker:
  `bash scripts/run_validation.sh`.

## Scope
Sandbox validation only. No third-party sites, no CAPTCHA or bot-protection
testing, no proxies, no fingerprint configuration.
