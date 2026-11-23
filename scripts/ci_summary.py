"""Report the validation verdict and decide the job's final exit code.

    python3 scripts/ci_summary.py --evidence logs/run/evidence --rc <validation exit code|missing> [--enforce]

Single source of truth for pass and fail in CI:
  - no acceptance.json                  -> ERROR (no verdict: preflight, build or runner failure)
  - verdict FAIL                        -> FAIL
  - verdict PASS-* but rc != 0          -> ERROR (inconsistent; never trust a PASS that the script did not return)
  - PASS-PARTIAL / PASS-FULL and rc==0  -> success (PARTIAL is annotated as a warning)
A running browser is never a pass on its own: the verdict comes only from
tests/acceptance.py, which gates on Firefox's own seccomp filters.

Writes Markdown to $GITHUB_STEP_SUMMARY when set (else stdout) and emits
::error / ::warning / ::notice annotations. With --enforce, exits non-zero
unless the outcome is a consistent PASS.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--rc", default="missing")
    ap.add_argument("--enforce", action="store_true")
    a = ap.parse_args()

    acc_path = Path(a.evidence) / "acceptance.json"
    try:
        acc = json.loads(acc_path.read_text())
        verdict = str(acc.get("verdict", ""))
        checks = acc.get("checks", [])
    except (OSError, ValueError):
        verdict, checks = "", []

    rc = a.rc.strip()
    if not verdict:
        outcome, level = "ERROR: no verdict produced (preflight, build or runner failure; see job log)", "error"
    elif verdict.startswith("FAIL"):
        outcome, level = "FAIL: acceptance criteria not met", "error"
    elif rc != "0":
        outcome, level = f"ERROR: verdict says {verdict!r} but the validation script exited {rc}", "error"
    elif verdict.startswith("PASS-FULL"):
        outcome, level = "PASS-FULL: Firefox seccomp and namespace layers active", "notice"
    elif verdict.startswith("PASS-PARTIAL"):
        outcome, level = "PASS-PARTIAL: Firefox seccomp layer active, namespace layer absent", "warning"
    else:
        outcome, level = f"ERROR: unrecognized verdict {verdict!r}", "error"

    lines = ["## Native x86_64 Firefox sandbox validation", "",
             f"**Outcome:** {outcome}", "",
             f"- Validation script exit code: `{rc}`",
             f"- Acceptance verdict: `{verdict or 'none'}`", ""]
    if checks:
        failed = [c for c in checks if c[0] not in ("info", "namespaces") and not c[2]]
        lines += ["| Result | Group | Check | Detail |", "|---|---|---|---|"]
        for g, n, ok, det in checks:
            mark = "info" if g in ("info", "namespaces") else ("PASS" if ok else "**FAIL**")
            lines.append(f"| {mark} | {g} | {n} | {str(det)[:120].replace('|', '/')} |")
        lines += ["", f"Gating checks failed: {len(failed)}"]
    lines += ["", "_Sanitized evidence is attached as the `native-sandbox-evidence` artifact when the leak scan passed._"]
    md = "\n".join(lines) + "\n"

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(md)
    else:
        print(md)
    print(f"::{level} title=Native sandbox validation::{outcome}")

    passed = level in ("notice", "warning")
    if a.enforce and not passed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
