#!/usr/bin/env bash
# Firefox sandbox validation on a native x86_64 Linux host. Run from the repository root:
#     bash scripts/run_validation.sh
# Used unchanged by .github/workflows/sandbox-validation.yml on ubuntu-24.04.
#
# It creates nothing outside this checkout except the Docker images and the
# containers of the `ffsbx` compose project (brought down on exit).
# It weakens nothing: no --privileged, no added capabilities, no seccomp
# changes, no sudo.
#
# Exit codes: 0 = PASS-PARTIAL or PASS-FULL, 1 = acceptance FAIL (or a build or
# run error after preflight), 2 = preflight refused the host. The verdict
# itself is in logs/run/evidence/acceptance.json.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=logs/run                 # host-owned, 0700: raw run material
EV="$OUT/evidence"           # the only path mounted into containers (see step 2)
F=docker/compose.hardened.yml
die() { echo "PREFLIGHT FAIL: $*" >&2; exit 2; }
step() { echo; echo "=== $*"; }

# --- 1. Host: refuse anything that is not native x86_64 Linux ------------------
step "1. host preflight"
[ "$(uname -s)" = Linux ] || die "not Linux ($(uname -s)); run on the Linux host or inside the WSL2 distro"
[ "$(uname -m)" = x86_64 ] || die "uname -m = $(uname -m), need x86_64"
if grep -qiE 'rosetta|qemu' /proc/self/maps; then die "a binary translator is mapped into this process"; fi
VIRT=$(systemd-detect-virt 2>/dev/null || true); VIRT=${VIRT:-unknown}
[ "$VIRT" != qemu ] || die "systemd-detect-virt=qemu (TCG emulation, not hardware virtualization)"
for t in docker python3 awk grep; do command -v "$t" >/dev/null || die "$t not installed"; done
docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin missing"
DARCH=$(docker info --format '{{.Architecture}}') || die "cannot talk to the Docker daemon"
[ "$DARCH" = x86_64 ] || die "Docker server architecture is $DARCH"
SECOPTS=$(docker info --format '{{json .SecurityOptions}}')
echo "$SECOPTS" | grep -q 'name=seccomp' || die "Docker seccomp is not active"
if echo "$SECOPTS" | grep -q 'unconfined'; then die "Docker default seccomp profile is unconfined"; fi
FREE_GB=$(df -Pk . | awk 'NR==2 {printf "%d", $4/1048576}')
[ "$FREE_GB" -ge 8 ] || die "only ${FREE_GB} GB free on the workspace filesystem; need >= 8"

# --- 2. Evidence directory -----------------------------------------------------
# Linux enforces bind-mount ownership: the container user (uid 10001) must be
# able to write, and the host user must be able to read afterwards. The parent
# stays 0700 (host user only); the evidence dir is 0777 so uid 10001 can write
# into it. Its files are made host-readable at the end by uid 10001 itself (step 10).
mkdir -p "$OUT"; chmod 700 "$OUT"
mkdir -p "$EV"; chmod 777 "$EV"
export LOGS_DIR="$PWD/$EV"

python3 - "$EV/host.json" "$VIRT" "$FREE_GB" <<'PY'
import json, platform, subprocess, sys
info = lambda f: subprocess.run(["docker", "info", "--format", f], capture_output=True, text=True).stdout.strip()
cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
json.dump({"machine": platform.machine(), "system": platform.system(), "kernel": platform.release(),
           "cpu": cpu, "virt": sys.argv[2], "disk_free_gb": int(sys.argv[3]),
           "docker_arch": info("{{.Architecture}}"), "docker_version": info("{{.ServerVersion}}"),
           "docker_os": info("{{.OperatingSystem}}"),
           "docker_security_options": json.loads(info("{{json .SecurityOptions}}"))},
          open(sys.argv[1], "w"), indent=2)
PY
cat "$EV/host.json"

# --- 3. Build (build-time network is unrestricted: apt, PyPI, GitHub release, Mozilla) --
step "3. build base (digest-pinned, hash-locked) and hardened images"
docker build -t ffsbx-base:local docker/base > "$OUT/build-base.log" 2>&1 \
  || { tail -n 40 "$OUT/build-base.log"; echo "BUILD FAIL: base image" >&2; exit 1; }
tail -n 3 "$OUT/build-base.log"
docker run --rm --network none --entrypoint python ffsbx-base:local -m invisible_playwright version \
  | tee "$EV/engine-version.txt"
grep -q "build 20261121043125" "$EV/engine-version.txt" || { echo "BUILD FAIL: engine build differs from the verified one" >&2; exit 1; }

# The upstream resolver a default-bridge container sees (only dnsmasq may reach it at runtime).
if [ -z "${UPSTREAM_DNS:-}" ]; then
  UPSTREAM_DNS=$(docker run --rm --network bridge --entrypoint sh ffsbx-base:local \
                 -c "awk '/^nameserver/{print \$2; exit}' /etc/resolv.conf")
fi
echo "$UPSTREAM_DNS" | grep -qE '^[0-9]+(\.[0-9]+){3}$' || { echo "UPSTREAM_DNS '$UPSTREAM_DNS' is not an IPv4 literal; set it explicitly" >&2; exit 1; }
case "$UPSTREAM_DNS" in 127.*) echo "UPSTREAM_DNS is loopback ($UPSTREAM_DNS); set the host's real resolver" >&2; exit 1;; esac
export UPSTREAM_DNS; echo "$UPSTREAM_DNS" > "$EV/upstream-dns.txt"; echo "upstream DNS detected"

docker compose -f "$F" build > "$OUT/build-compose.log" 2>&1 \
  || { tail -n 40 "$OUT/build-compose.log"; echo "BUILD FAIL: hardened/egress images" >&2; exit 1; }
docker compose -f "$F" config --format json > "$EV/compose-config.json"

cleanup() { docker compose -f "$F" down >/dev/null 2>&1 || true; }
trap cleanup EXIT
run_browser() { docker compose -f "$F" run --rm -T "$@"; }

# --- 4. Docker runtime config + seccomp primitives --------------------------------
step "4. egress up, Docker runtime config, seccomp primitives"
docker compose -f "$F" up -d --wait egress
docker inspect "$(docker compose -f "$F" ps -q egress)" > "$EV/egress-inspect.json"
docker compose -f "$F" exec -T egress nft list table inet egress > "$EV/ruleset-loaded.txt"
run_browser -e PRIMITIVES_OUT=/app/logs/primitives.json browser python -I tests/seccomp_primitives.py >/dev/null || true

# --- 5. Egress validation ------------------------------------------------------------
step "5. egress probe"
UNAPPROVED_IP=$(python3 -c "import socket; print(socket.gethostbyname('example.org'))")
run_browser -e PROBE_UNAPPROVED_IP="$UNAPPROVED_IP" -e PROBE_UPSTREAM_DNS="$UPSTREAM_DNS" \
  browser python -I tests/egress_probe.py > "$OUT/egress-probe.txt" 2>&1 || true
tail -n 1 "$OUT/egress-probe.txt"

# --- 6-8. Firefox: per-process seccomp vs baseline, namespaces, engine sandbox log
step "6-8. Firefox sandbox diagnostics"
run_browser -e SANDBOX_DIAG_NAME=sandbox-diag.json browser python -I tests/sandbox_diag.py > "$OUT/sandbox-diag.txt" 2>&1 || true

# --- 9. Smoke test on a fresh egress (clean evidence), then egress evidence ----------
step "9. smoke test (strict cleanup) and egress evidence"
docker compose -f "$F" down >/dev/null 2>&1
docker compose -f "$F" up -d --wait egress
run_browser browser > "$OUT/smoke-stdout.log" 2>&1 || true
grep -E "STEP|FAILED" "$OUT/smoke-stdout.log" | cut -c1-160 || true
docker compose -f "$F" exec -T egress nft list table inet egress > "$EV/ruleset-after-smoke.txt"
docker compose -f "$F" logs --no-log-prefix egress > "$EV/dnsmasq-smoke.log"

# --- 10. Make the container-written files readable by the host user ------------------
# Done by uid 10001 itself (owner of those files), in a container with no network,
# no capabilities, read-only rootfs. No sudo, no root.
docker run --rm --network none --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --entrypoint find -v "$PWD/$EV":/e ffsbx-browser:local \
  /e -user 10001 -exec chmod u+rwX,go+rX {} +

# --- Acceptance -------------------------------------------------------------------
step "acceptance"
python3 tests/acceptance.py "$EV"
