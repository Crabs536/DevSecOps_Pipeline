#!/usr/bin/env python3
"""Trivy image-report baseline comparison for DevSecOps Pipeline (Milestone 5).

Only new/escalated findings affect the PR image gate. Requires two successful
Trivy JSON scans. No network calls and no secrets.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

RANK = {"UNKNOWN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
DECISION_EXIT = {"PASS": 0, "FAIL": 1, "REVIEW": 2}


def read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def parse_trivy(payload: Any) -> list[dict[str, Any]]:
    """Validate real Trivy JSON structure, flatten vulnerabilities safely."""
    if not isinstance(payload, dict) or not isinstance(payload.get("SchemaVersion"), int):
        raise ValueError("Invalid Trivy JSON: missing integer SchemaVersion (refusing untrusted report)")
    results = payload.get("Results")
    if not isinstance(results, list):
        raise ValueError("Invalid Trivy JSON: missing Results list (refusing untrusted report)")
    findings: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Invalid Trivy JSON: Results entry is not an object")
        vulns = item.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            raise ValueError("Invalid Trivy JSON: Vulnerabilities is not a list")
        for vuln in vulns:
            if not isinstance(vuln, dict):
                raise ValueError("Invalid Trivy JSON: vulnerability not an object")
            pkg = vuln.get("PkgName")
            vid = vuln.get("VulnerabilityID")
            if not isinstance(pkg, str) or not pkg or not isinstance(vid, str) or not vid:
                raise ValueError("Invalid Trivy JSON: vulnerability missing PkgName/VulnerabilityID")
            sev = vuln.get("Severity") or "UNKNOWN"
            sev = str(sev).upper()
            if sev not in RANK:
                sev = "UNKNOWN"
            # InstalledVersion is not part of identity: changing a vulnerable
            # version without removing the CVE must not be called a new CVE.
            key = (str(item.get("Class", "")), str(item.get("Type", "")),
                   str(item.get("Target", "")), pkg, vid)
            findings.append({
                "key": key,
                "severity": sev,
                "id": vid,
                "package": pkg,
                "target": key[2],
                "installed": str(vuln.get("InstalledVersion", "")),
                "fixed": str(vuln.get("FixedVersion", "")),
            })
    return findings


def compare(base: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, Any]:
    """Pair repeated findings one-to-one, respecting severity escalation."""
    left: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    right: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for f in base:
        left[f["key"]].append(f)
    for f in current:
        right[f["key"]].append(f)
    new_or_escalated: list[dict[str, Any]] = []
    existing = resolved = 0
    for key in sorted(set(left) | set(right)):
        older = list(left[key])
        newer = list(right[key])
        # First, consume matches with exactly the same severity.
        for severity in RANK:
            old_same = [f for f in older if f["severity"] == severity]
            cur_same = [f for f in newer if f["severity"] == severity]
            n = min(len(old_same), len(cur_same))
            for _ in range(n):
                older.remove(old_same.pop())
                newer.remove(cur_same.pop())
            existing += n

        # Match remaining same-identity entries; priority is detecting severity increases.
        for item in list(newer):
            if older:
                candidate = min(older, key=lambda b: abs(RANK[b["severity"]] - RANK[item["severity"]]))
                older.remove(candidate)
                if RANK[item["severity"]] > RANK[candidate["severity"]]:
                    new_or_escalated.append({"change": "ESCALATED", "previous_severity": candidate["severity"], **item})
                else:
                    existing += 1
            else:
                new_or_escalated.append({"change": "NEW", **item})
        resolved += len(older)
    return {"new_or_escalated": new_or_escalated, "existing": existing,
            "resolved": resolved, "baseline_total": len(base), "current_total": len(current)}


def evaluate(changes: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    threshold = str(policy.get("fail_on", "HIGH")).upper()
    unknown_policy = str(policy.get("unknown", "review")).lower()
    if threshold not in ("MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError("Invalid policy: fail_on must be MEDIUM, HIGH, or CRITICAL")
    if unknown_policy not in ("review", "block", "allow"):
        raise ValueError("Invalid policy: unknown must be review, block, or allow")
    items = changes["new_or_escalated"]
    blocking = [v for v in items if RANK[v["severity"]] >= RANK[threshold] or
                (v["severity"] == "UNKNOWN" and unknown_policy == "block")]
    reviewing = [v for v in items if v["severity"] == "UNKNOWN" and unknown_policy == "review"]
    decision = "FAIL" if blocking else "REVIEW" if reviewing else "PASS"
    return {**changes, "decision": decision, "fail_on": threshold, "unknown": unknown_policy,
            "blocking": len(blocking), "needs_review": len(reviewing),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            # Tuple keys are not JSON-serializable as dict keys but lists are fine.
            "new_or_escalated": [dict(f, key=list(f["key"])) for f in items]}


def create_summary(report: dict[str, Any]) -> str:
    lines = ["# Container Image Security Gate (Trivy)", "",
             f"- Decision: **{report['decision']}**",
             f"- Threshold: **{report['fail_on']}**; UNKNOWN: **{report['unknown']}**",
             f"- Baseline findings: **{report['baseline_total']}**",
             f"- PR image findings: **{report['current_total']}**",
             f"- Existing: **{report['existing']}**; resolved: **{report['resolved']}**",
             f"- New or escalated: **{len(report['new_or_escalated'])}**",
             f"- Blocking: **{report['blocking']}**; needs review: **{report['needs_review']}**", "",
             "## New / Escalated vulnerabilities (up to 50)", "",
             "| Change | Severity | Advisory | Package | Image target | Version | Fixed in |",
             "|---|---|---|---|---|---|---|" ]
    rows = report["new_or_escalated"]
    if not rows:
        lines.append("| - | - | - | - | No new vulnerabilities | - | - |")
    else:
        for f in sorted(rows, key=lambda x: -RANK[x["severity"]])[:50]:
            values = [f["change"], f["severity"], f["id"], f["package"],
                      f["target"], f["installed"], f["fixed"]]
            # Safe Markdown table text; never render raw HTML or full package details.
            safe = [str(v).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;")[:180] for v in values]
            lines.append("| " + " | ".join(safe) + " |")
    lines += ["", "_Only new/escalated vulnerabilities affect this gate. Known vulnerabilities still require separate remediation._", "",
              "_A passing gate does not mean the image is vulnerability-free. The scan and comparison both need trusted, complete reports._", ""]
    return "\n".join(lines)


def run_compare(args: argparse.Namespace) -> int:
    base = parse_trivy(read_json(args.baseline))
    current = parse_trivy(read_json(args.current))
    policy = read_json(args.policy)
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    report = evaluate(compare(base, current), policy)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "report.json").open("w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)
    (out / "summary.md").write_text(create_summary(report), encoding="utf-8")
    print(f"Container Gate: {report['decision']}; new/escalated={len(report['new_or_escalated'])}; "
          f"existing={report['existing']}; resolved={report['resolved']}; "
          f"blocking={report['blocking']}; review={report['needs_review']}")
    return DECISION_EXIT[report["decision"]]


def self_test() -> None:
    mk = lambda sev, vid="CVE-EXAMPLE-1": {"SchemaVersion": 2, "Results": [{"Target": "alpine", "Type": "alpine", "Class": "os-pkgs", "Vulnerabilities": [{"VulnerabilityID": vid, "PkgName": "busybox", "Severity": sev}]}]}
    zero = {"SchemaVersion": 2, "Results": []}
    p = {"fail_on": "HIGH", "unknown": "review"}
    assert evaluate(compare(parse_trivy(zero), parse_trivy(zero)), p)["decision"] == "PASS"
    assert evaluate(compare(parse_trivy(zero), parse_trivy(mk("HIGH"))), p)["decision"] == "FAIL"
    assert evaluate(compare(parse_trivy(zero), parse_trivy(mk("MEDIUM"))), p)["decision"] == "PASS"
    assert evaluate(compare(parse_trivy(zero), parse_trivy(mk("UNKNOWN"))), p)["decision"] == "REVIEW"
    assert evaluate(compare(parse_trivy(mk("MEDIUM")), parse_trivy(mk("HIGH"))), p)["decision"] == "FAIL"
    assert evaluate(compare(parse_trivy(mk("HIGH")), parse_trivy(mk("HIGH"))), p)["decision"] == "PASS"
    try: parse_trivy({"Results": []})
    except ValueError: pass
    else: raise AssertionError("Trivy schema check failed")
    print("[PASS] Container gate self-test: schema validation, PASS/FAIL/REVIEW, escalation")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare Trivy JSON image scan results")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("self-test")
    cmd = subs.add_parser("compare")
    cmd.add_argument("--baseline", required=True)
    cmd.add_argument("--current", required=True)
    cmd.add_argument("--policy", required=True)
    cmd.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            self_test()
            return 0
        return run_compare(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Container comparison aborted (fail closed): {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
