#!/usr/bin/env python3
"""Increase GitHub Actions scanner job timeouts without changing gate logic.

Default: dry run. Use --apply to write after examining the diff.
"""
import argparse
from pathlib import Path
import re
import sys

JOBS = {
    ".github/workflows/devsecops-pr-gate.yml": ("pr-security-gate", 120),
    ".github/workflows/devsecops-container-gate.yml": ("container-security-gate", 120),
}


def patch_job_timeout(text: str, job_name: str, minutes: int) -> str:
    # Match only the named job's own setting, never a step timeout or unrelated job.
    pattern = re.compile(
        rf"(?m)(^  {re.escape(job_name)}:\s*\n(?:(?!^  [\w-]+:).)*?^    timeout-minutes:\s*)(\d+)(\s*$)",
        re.S,
    )
    found = pattern.search(text)
    if not found:
        raise ValueError(f"Job {job_name} or its timeout-minutes field not found")
    old = int(found.group(2))
    print(f"{job_name}: {old} -> {max(old, minutes)} minutes")
    return text[:found.start(2)] + str(max(old, minutes)) + text[found.end(2):]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = ap.parse_args()
    root = Path(args.repo)
    for rel, (job_name, minutes) in JOBS.items():
        p = root / rel
        if not p.is_file():
            print(f"[SKIP] {p} missing")
            continue
        previous = p.read_text(encoding="utf-8")
        updated = patch_job_timeout(previous, job_name, minutes)
        if args.apply and previous != updated:
            p.write_text(updated, encoding="utf-8")
            print(f"[UPDATED] {p}")
        else:
            print(f"[{'UNCHANGED' if previous == updated else 'DRY-RUN'}] {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
