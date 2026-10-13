#!/usr/bin/env python3
"""Local DevSecOps starter: Semgrep, OSV-Scanner, Gitleaks and Checkov.

Requires Python 3.11+. Python dependencies are in requirements.txt.
OSV-Scanner and Gitleaks are separately downloaded by 'setup-tools'.
Never executes code from the scanned repository directly.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
TOOL_DIR = Path(os.environ.get("DEVSECOPS_TOOL_DIR", str(APP_DIR / ".tools" / "bin"))).expanduser().resolve()
DEFAULT_TAGS = {"gitleaks": "v8.30.1", "osv-scanner": "v2.6.0"}
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
SCORES = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", ".tox", ".tools", "reports", "dist", "build", "__pycache__", ".devsecops-reports"}
MANIFEST_NAMES = {"requirements.txt", "pipfile.lock", "poetry.lock", "uv.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "go.mod", "go.sum", "cargo.lock", "gemfile.lock", "composer.lock", "gradle.lockfile", "pom.xml", "packages.lock.json", "packages.config", "pubspec.lock", "bom.json"}
SCAN_KEYS = ("sast", "sca", "secret", "iac")
SCANNER_NAMES = {"sast": "SAST", "sca": "SCA", "secret": "SECRET", "iac": "IAC"}
DEFAULT_POLICY_PATH = APP_DIR / "security-policy.json"
EXIT_CODES = {"PASS": 0, "FAIL": 1, "REVIEW": 1, "ERROR": 2}



def log(message: str) -> None:
    print(message, flush=True)


def shorten(value: Any, max_len: int = 500) -> str:
    return str(value or "").replace("\x00", " ").replace("\r", " ").replace("\n", " ")[:max_len]


def relative_file(path_value: Any, root: Path) -> str:
    p = str(path_value or "")
    if not p:
        return ""
    if p.startswith("file://"):
        p = p[7:]
    try:
        return str(Path(p).resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return p


def norm_severity(value: Any) -> str:
    s = str(value or "").upper().strip()
    synonyms = {"ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "MODERATE": "MEDIUM", "INFORMATIONAL": "INFO", "NONE": "INFO"}
    s = synonyms.get(s, s)
    return s if s in SEVERITIES else "UNKNOWN"


def cvss_level(number: float) -> str:
    if number >= 9.0:
        return "CRITICAL"
    if number >= 7.0:
        return "HIGH"
    if number >= 4.0:
        return "MEDIUM"
    if number > 0:
        return "LOW"
    return "INFO"


def osv_severity(vulnerability: dict[str, Any]) -> str:
    """Use CVSS base scores if available; never invent a severity."""
    candidates: list[float] = []
    db = vulnerability.get("database_specific") or {}
    label = db.get("severity") if isinstance(db, dict) else None
    if label:
        label = norm_severity(label)
        if label != "UNKNOWN":
            return label
    for entry in vulnerability.get("severity") or []:
        score_text = str((entry or {}).get("score", ""))
        try:
            candidates.append(float(score_text))
            continue
        except ValueError:
            pass
        if score_text.startswith("CVSS:3") or score_text.startswith("CVSS:4"):
            try:
                from cvss import CVSS3, CVSS4
                vector = CVSS4(score_text) if score_text.startswith("CVSS:4") else CVSS3(score_text)
                candidates.append(float(vector.scores()[0]))
            except (ValueError, ImportError, IndexError, TypeError):
                pass
    return cvss_level(max(candidates)) if candidates else "UNKNOWN"


def parse_semgrep(obj: Any, root: Path) -> list[dict[str, Any]]:
    if not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
        raise ValueError("Semgrep output has no results array")
    findings = []
    for item in obj["results"]:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") or {}
        findings.append({
            "scanner": "SAST", "rule_id": shorten(item.get("check_id"), 200),
            "severity": norm_severity(extra.get("severity")),
            "file": relative_file(item.get("path"), root),
            "line": (item.get("start") or {}).get("line"),
            "message": shorten(extra.get("message")),
            # Only store a digest of Semgrep's optional match fingerprint, never source lines.
            **({"fingerprint": hashlib.sha256(str(extra["fingerprint"]).encode("utf-8")).hexdigest()}
               if extra.get("fingerprint") else {}),
        })
    return findings


def parse_osv(obj: Any, root: Path) -> list[dict[str, Any]]:
    if not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
        raise ValueError("OSV output has no results array")
    findings: list[dict[str, Any]] = []
    for result in obj["results"]:
        source = (result or {}).get("source") or {}
        file_path = relative_file(source.get("path"), root)
        for package_record in (result or {}).get("packages") or []:
            package = package_record.get("package") or {}
            vuln_list = package_record.get("vulnerabilities") or []
            by_id = {v.get("id"): v for v in vuln_list if isinstance(v, dict) and v.get("id")}
            groups = package_record.get("groups") or []
            if not groups:
                groups = [{"ids": [v.get("id")]} for v in vuln_list if isinstance(v, dict)]
            seen = set()
            for group in groups:
                ids = [str(i) for i in group.get("ids", []) if i]
                if not ids:
                    continue
                fingerprint = tuple(sorted(ids))
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                severity_parts = [osv_severity(by_id[i]) for i in ids if i in by_id]
                known_levels = [s for s in severity_parts if s in SCORES]
                sev = max(known_levels, key=SCORES.get) if known_levels else "UNKNOWN"
                preferred_id = next((i for i in ids if i.startswith("CVE-")), ids[0])
                package_name = shorten(package.get("name"), 180)
                package_version = shorten(package.get("version"), 80)
                findings.append({
                    "scanner": "SCA", "rule_id": preferred_id, "severity": sev,
                    "file": file_path, "line": None,
                    "message": f"{package_name}@{package_version}: {', '.join(ids[:6])}",
                    "package": package_name, "version": package_version,
                })
    return findings


def parse_gitleaks(obj: Any, root: Path) -> list[dict[str, Any]]:
    if obj is None:
        return []
    if not isinstance(obj, list):
        raise ValueError("Gitleaks output is not a JSON array")
    findings = []
    for item in obj:
        if not isinstance(item, dict):
            continue
        # Deliberately NEVER export: Secret, Match, Line, Author, Email, Message.
        findings.append({
            "scanner": "SECRET", "rule_id": shorten(item.get("RuleID"), 200),
            "severity": "HIGH", "file": relative_file(item.get("File"), root),
            "line": item.get("StartLine"),
            "message": "Potential credential exposure (details withheld)",
        })
    return findings


def parse_checkov(obj: Any, root: Path) -> list[dict[str, Any]]:
    # Multiple IaC frameworks can generate a list of report objects.
    reports = obj if isinstance(obj, list) else [obj]
    findings = []
    for report in reports:
        if not isinstance(report, dict) or not isinstance(report.get("results"), dict):
            raise ValueError("Checkov output has no results object")
        framework = shorten(report.get("check_type"), 60)
        for failed in report["results"].get("failed_checks") or []:
            loc = failed.get("file_line_range") or []
            findings.append({
                "scanner": "IAC", "rule_id": shorten(failed.get("check_id"), 200),
                "severity": norm_severity(failed.get("severity")),
                "file": relative_file(failed.get("file_path"), root),
                "line": loc[0] if isinstance(loc, list) and loc else None,
                "message": shorten(failed.get("check_name")),
                "framework": framework,
                "resource": shorten(failed.get("resource"), 240),
            })
    return findings


def iter_project_files(root: Path):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in EXCLUDED_DIRS]
        for name in files:
            yield Path(dirpath) / name


def has_dependency_files(root: Path) -> bool:
    for p in iter_project_files(root):
        name = p.name.lower()
        if name in MANIFEST_NAMES or (name.startswith("requirements-") and name.endswith(".txt")) or name.endswith(".cdx.json") or name.endswith(".spdx.json"):
            return True
    return False


def has_iac_files(root: Path) -> bool:
    for p in iter_project_files(root):
        name = p.name.lower()
        if name.endswith((".tf", ".tf.json", ".dockerfile")) or name == "dockerfile" or name.startswith("dockerfile.") or name in {"chart.yaml", "chart.yml"}:
            return True
        if name.endswith((".yaml", ".yml", ".json")):
            lower_parts = [part.lower() for part in p.parts]
            if any(x in lower_parts for x in {"k8s", "kubernetes", "terraform", "helm", "cloudformation"}):
                return True
            if name in {"template.yaml", "template.yml", "cloudformation.yaml", "cloudformation.yml"}:
                return True
    return False


def find_tool(name: str) -> str | None:
    local = TOOL_DIR / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    return shutil.which(name)


def doctor() -> int:
    log("Tool check (Python 3.11+ recommended):")
    missing = []
    commands = {"semgrep": ["--version"], "checkov": ["--version"], "gitleaks": ["version"], "osv-scanner": ["--version"]}
    for tool, version_args in commands.items():
        executable = find_tool(tool)
        if not executable:
            log(f"  [MISSING] {tool}")
            missing.append(tool)
            continue
        try:
            cp = subprocess.run([executable] + version_args, capture_output=True, text=True, timeout=20, check=False)
            if cp.returncode != 0:
                log(f"  [ERROR]   {tool}: version check returned {cp.returncode}")
                missing.append(tool)
                continue
            first_line = (cp.stdout.strip() or cp.stderr.strip()).splitlines()
            label = shorten(first_line[0], 100) if first_line else "version unavailable"
            log(f"  [FOUND]   {tool}: {label}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            log(f"  [ERROR]   {tool}: {exc}")
            missing.append(tool)
    try:
        from cvss import CVSS3  # noqa: F401
        log("  [FOUND]   cvss Python library")
    except ImportError:
        missing.append("cvss")
        log("  [MISSING] cvss Python library")
    if missing:
        log("Fix missing items with: pip install -r requirements.txt; python devsecops.py setup-tools")
        return 2
    log("All required tools are available.")
    return 0


def github_release(repo: str, tag: str) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "devsecops-starter/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def download_verified_asset(asset: dict[str, Any]) -> bytes:
    digest = asset.get("digest") or ""
    if not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", digest):
        raise RuntimeError("Release asset has no valid GitHub SHA-256 digest. Installation refused.")
    url = asset.get("browser_download_url", "")
    if not url.startswith("https://github.com/"):
        raise RuntimeError("Unexpected release asset URL")
    req = urllib.request.Request(url, headers={"User-Agent": "devsecops-starter/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(150 * 1024 * 1024 + 1)
    if len(data) > 150 * 1024 * 1024:
        raise RuntimeError("Release asset too large")
    if hashlib.sha256(data).hexdigest().lower() != digest[7:].lower():
        raise RuntimeError("Release SHA-256 mismatch. Installation refused.")
    return data


def get_binary_from_asset(name: str, raw: bytes) -> bytes:
    with io.BytesIO(raw) as stream:
        if name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=stream, mode="r:gz") as archive:
                for member in archive.getmembers():
                    if member.isfile() and Path(member.name).name in {"gitleaks", "osv-scanner"}:
                        f = archive.extractfile(member)
                        if f is not None:
                            return f.read()
            raise RuntimeError("Expected executable not found in tar.gz")
        if name.endswith(".zip"):
            with zipfile.ZipFile(stream) as archive:
                for member in archive.namelist():
                    if Path(member).name in {"gitleaks", "osv-scanner"}:
                        return archive.read(member)
            raise RuntimeError("Expected executable not found in zip")
    return raw


def setup_tools(osv_tag: str, gitleaks_tag: str, force: bool) -> int:
    if platform.system() != "Linux":
        log("setup-tools supports Linux/WSL. For macOS/Windows, install binaries manually from upstream releases.")
        return 2
    arch = platform.machine().lower()
    if arch in {"x86_64", "amd64"}:
        osv_arch, gitleaks_arch = "amd64", "x64"
    elif arch in {"aarch64", "arm64"}:
        osv_arch = gitleaks_arch = "arm64"
    else:
        log(f"Unsupported architecture for auto-installer: {arch}")
        return 2
    specs = [
        ("gitleaks", "gitleaks/gitleaks", gitleaks_tag, f"linux_{gitleaks_arch}"),
        ("osv-scanner", "google/osv-scanner", osv_tag, f"linux_{osv_arch}"),
    ]
    TOOL_DIR.mkdir(parents=True, exist_ok=True)
    for tool, repo, tag, platform_label in specs:
        dest = TOOL_DIR / tool
        if dest.exists() and not force:
            log(f"[SKIP] {tool} already installed at {dest}; use --force to replace")
            continue
        log(f"[DOWNLOAD] {repo} {tag} ({platform_label})")
        try:
            release = github_release(repo, tag)
            assets = release.get("assets") or []
            match = [a for a in assets if platform_label in a.get("name", "").lower() and a.get("name", "").lower().startswith(tool)]
            if not match:
                raise RuntimeError("No matching release asset (check upstream release and platform)")
            # Prefer .tar.gz or raw file, never checksum or provenance files.
            match = [a for a in match if not any(s in a.get("name", "").lower() for s in ("checksum", "intoto", ".sig", ".pem"))]
            match.sort(key=lambda a: 0 if a.get("name", "").endswith(".tar.gz") else 1)
            if not match:
                raise RuntimeError("No installable asset found")
            chosen = match[0]
            binary = get_binary_from_asset(chosen["name"], download_verified_asset(chosen))
            if not binary or len(binary) < 1_024:
                raise RuntimeError("Downloaded binary content is unexpectedly small")
            with tempfile.NamedTemporaryFile(dir=TOOL_DIR, delete=False) as f:
                temp_file = Path(f.name)
                f.write(binary)
            try:
                temp_file.chmod(0o755)
                temp_file.replace(dest)
            finally:
                temp_file.unlink(missing_ok=True)
            log(f"[OK] {tool} installed to {dest}")
        except Exception as exc:
            log(f"[ERROR] {tool}: {shorten(exc, 350)}")
            return 2
    log("Binary installation finished. Run: python devsecops.py doctor")
    return 0


def run_command(cmd: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, errors="replace")


def semgrep_failure_hint(cp: subprocess.CompletedProcess[str], config: str) -> str:
    """Explain common Semgrep failures without copying source/secret-bearing stderr into reports."""
    stderr = (cp.stderr or "").lower()
    prefix = f"Semgrep failed to produce valid JSON (exit={cp.returncode}, config={config!r})."
    if "metrics" in stderr and ("auto" in stderr or "configuration" in stderr):
        return prefix + " Semgrep auto configuration can require metrics. Retry with --semgrep-config p/default or a local YAML ruleset."
    if any(term in stderr for term in ("connection", "timed out", "certificate", "ssl", "network", "failed to download")):
        return prefix + " Registry/network/TLS error is possible. Check connectivity or use an existing local YAML ruleset."
    if "no such file" in stderr or "not found" in stderr:
        return prefix + " A ruleset or file may be missing. Verify the --semgrep-config value."
    if "out of memory" in stderr or "memoryerror" in stderr:
        return prefix + " Semgrep may have exhausted memory. Reduce concurrency or scan scope."
    return prefix + " Run Semgrep directly to inspect its stderr; stderr is not copied into the report to avoid leaking source data."


def scan_one(key: str, root: Path, opts: argparse.Namespace) -> dict[str, Any]:
    begin = time.monotonic()
    results: dict[str, Any] = {"status": "ERROR", "count": 0, "findings": [], "elapsed_seconds": 0.0, "error": None, "exit_code": None}
    tool_map = {"sast": "semgrep", "sca": "osv-scanner", "secret": "gitleaks", "iac": "checkov"}
    try:
        if key == "sca" and not has_dependency_files(root):
            results.update(status="SKIPPED", error="No supported dependency manifest/lockfile found")
            return results
        if key == "iac" and not has_iac_files(root):
            results.update(status="SKIPPED", error="No recognized IaC file found")
            return results
        executable = find_tool(tool_map[key])
        if not executable:
            results["error"] = f"{tool_map[key]} executable not installed; run doctor/setup-tools"
            return results
        if key == "sast":
            cmd = [executable, "scan", "--config", opts.semgrep_config, "--json", "--metrics=off", str(root)]
            cp = run_command(cmd, root, opts.timeout)
            if not cp.stdout.strip():
                raise RuntimeError(semgrep_failure_hint(cp, opts.semgrep_config))
            try:
                data = json.loads(cp.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(semgrep_failure_hint(cp, opts.semgrep_config) + f" JSON parse error at character {exc.pos}.") from exc
            results["findings"] = parse_semgrep(data, root)
            if cp.returncode != 0 or any((e or {}).get("level") == "error" for e in data.get("errors") or []):
                raise RuntimeError(f"Semgrep returned a scan error (exit={cp.returncode}). Run Semgrep directly to inspect stderr.")
        elif key == "sca":
            cmd = [executable, "scan", "source", "--format", "json", "-r", str(root)]
            cp = run_command(cmd, root, opts.timeout)
            data = json.loads(cp.stdout)
            results["findings"] = parse_osv(data, root)
            if cp.returncode not in (0, 1) or (cp.returncode == 1 and not results["findings"]):
                raise RuntimeError(f"OSV returned unexpected status {cp.returncode}. Inspect CLI output locally; raw stderr is omitted for confidentiality.")
        elif key == "secret":
            with tempfile.TemporaryDirectory(prefix="devsecops-secret-") as tempdir:
                report = Path(tempdir) / "gitleaks.json"
                cmd = [executable, opts.secrets_mode, str(root), "--report-format", "json", "--report-path", str(report), "--redact=100", "--no-banner"]
                cp = run_command(cmd, root, opts.timeout)
                if not report.exists():
                    if cp.returncode == 0:
                        data = []
                    else:
                        raise RuntimeError(f"Gitleaks returned {cp.returncode} and generated no JSON report")
                else:
                    body = report.read_text(encoding="utf-8").strip()
                    data = json.loads(body) if body else []
                results["findings"] = parse_gitleaks(data, root)
                if cp.returncode not in (0, 1) or (cp.returncode == 1 and not results["findings"]):
                    raise RuntimeError(f"Gitleaks returned unexpected status {cp.returncode}")
        else:
            cmd = [executable, "--directory", str(root), "--output", "json", "--quiet", "--soft-fail", "--skip-framework", "secrets"]
            cp = run_command(cmd, root, opts.timeout)
            data = json.loads(cp.stdout)
            results["findings"] = parse_checkov(data, root)
            if cp.returncode != 0:
                raise RuntimeError(f"Checkov returned unexpected status {cp.returncode}. Inspect CLI output locally; raw stderr is omitted for confidentiality.")
        results.update(status="COMPLETE", count=len(results["findings"]), exit_code=cp.returncode)
    except subprocess.TimeoutExpired:
        results["error"] = f"Scanner exceeded {opts.timeout}s timeout"
    except (OSError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) as exc:
        results["error"] = shorten(exc, 400)
    finally:
        if "cp" in locals():
            results["exit_code"] = cp.returncode
        results["elapsed_seconds"] = round(time.monotonic() - begin, 2)
        results["count"] = len(results["findings"])
    return results


# --- Policy and PR comparison ------------------------------------------------

def load_policy(filename: str | Path | None) -> dict[str, Any]:
    """Load a defensively validated, trusted policy. Never load policy from untrusted PR checkout."""
    location = Path(filename).expanduser() if filename else DEFAULT_POLICY_PATH
    if location.is_file():
        config = json.loads(location.read_text(encoding="utf-8"))
    elif filename:
        raise ValueError(f"Policy file not found: {location}")
    else:
        config = {"schema_version": 1, "fail_on": "HIGH", "unknown_behavior": "review", "overrides": {}}
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise ValueError("Policy must be a JSON object with schema_version=1")
    fail_on = str(config.get("fail_on", "HIGH")).upper()
    if fail_on not in (*SCORES, "NONE"):
        raise ValueError("Policy fail_on must be LOW, MEDIUM, HIGH, CRITICAL, INFO or NONE")
    unknown = str(config.get("unknown_behavior", "review")).lower()
    if unknown not in {"block", "review", "warn"}:
        raise ValueError("unknown_behavior must be block, review or warn")
    overrides = config.get("overrides") or {}
    if not isinstance(overrides, dict):
        raise ValueError("overrides must be a mapping by scanner")
    for scanner, rules in overrides.items():
        if scanner not in SCANNER_NAMES.values() or not isinstance(rules, dict):
            raise ValueError("overrides must map SAST/SCA/SECRET/IAC to rule-id severity maps")
        for rule_id, severity in rules.items():
            if not isinstance(rule_id, str) or not rule_id.strip() or str(severity).upper() not in SCORES:
                raise ValueError("Each override needs a nonempty rule ID and a known severity")
    return {"schema_version": 1, "fail_on": fail_on, "unknown_behavior": unknown,
            "overrides": {k: {rule: str(value).upper() for rule, value in v.items()} for k,v in overrides.items()}}


def selected_policy(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    cfg = json.loads(json.dumps(config))
    if getattr(args, "fail_on", None) is not None:
        cfg["fail_on"] = args.fail_on.upper()
    if getattr(args, "unknown_policy", None) is not None:
        cfg["unknown_behavior"] = args.unknown_policy
    if getattr(args, "allow_unknown", False):
        cfg["unknown_behavior"] = "warn"
    return cfg


def apply_policy(findings: list[dict[str, Any]], policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Reapply severity on both baseline and PR using exactly the SAME trusted policy."""
    mapped: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        original = norm_severity(item.get("original_severity", item.get("severity")))
        override = policy["overrides"].get(str(item.get("scanner", "")).upper(), {}).get(str(item.get("rule_id", "")))
        item["original_severity"] = original
        if override and (original == "UNKNOWN" or SCORES[override] > SCORES[original]):
            item["severity"] = override
            item["severity_source"] = "policy_override"
        else:
            # Rule overrides must not silently downgrade an existing scanner severity.
            item["severity"] = original
            item["severity_source"] = "scanner" if original != "UNKNOWN" else "unclassified"
        mapped.append(item)
    return mapped


def gate_result(findings: list[dict[str, Any]], policy: dict[str, Any]) -> tuple[str, int, int]:
    if policy["fail_on"] == "NONE":
        return "PASS", 0, 0
    threshold = SCORES[policy["fail_on"]]
    blocked = sum(SCORES.get(str(f.get("severity")), -1) >= threshold for f in findings)
    unknowns = sum(f.get("severity") == "UNKNOWN" for f in findings)
    if policy["unknown_behavior"] == "block":
        blocked += unknowns
    reviews = unknowns if policy["unknown_behavior"] == "review" else 0
    state = "FAIL" if blocked else "REVIEW" if reviews else "PASS"
    return state, blocked, reviews


def _safe_md(value: Any) -> str:
    return shorten(value, 170).replace("|", "\\|").replace("`", "'")


def make_summary(report: dict[str, Any]) -> str:
    policy = report["policy"]
    lines = [
        "# DevSecOps security scan", "",
        f"- Target: `{_safe_md(report['target'])}`",
        f"- Time (UTC): `{report['generated_at_utc']}`",
        f"- Overall: **{report['status']}**",
        f"- Threshold: `{policy['fail_on']}`; unknown: `{policy['unknown_behavior']}`",
        f"- Findings: **{report['total_findings']}**",
        f"- Blocking: **{report['blocking_findings']}**; manual review: **{report['review_findings']}**",
        "- Severity: " + ", ".join(f"{k}={report['by_severity'].get(k,0)}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")),
        "", "| Scanner | Status | Findings | Seconds |", "|---|---|---:|---:|",
    ]
    for scanner in SCAN_KEYS:
        item = report["scans"].get(scanner)
        if item:
            lines.append(f"| {scanner.upper()} | {item['status']} | {item['count']} | {item['elapsed_seconds']} |")
    lines += ["", "## Findings (up to 100)", "", "| Scanner | Severity | Rule ID | File / line | Message |", "|---|---|---|---|---|"]
    all_findings = [f for item in report["scans"].values() for f in item.get("findings", [])]
    priority = {"CRITICAL": 5, "HIGH": 4, "UNKNOWN": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    all_findings.sort(key=lambda f: priority.get(f.get("severity"), 3), reverse=True)
    for f in all_findings[:100]:
        location = str(f.get("file", "")) + (f":{f['line']}" if f.get("line") is not None else "")
        lines.append(f"| {_safe_md(f.get('scanner'))} | {_safe_md(f.get('severity'))} | {_safe_md(f.get('rule_id'))} | {_safe_md(location)} | {_safe_md(f.get('message'))} |")
    if not all_findings:
        lines.append("| - | - | - | - | No findings reported |")
    errors = [(name, detail.get("error")) for name, detail in report["scans"].items() if detail.get("error")]
    if errors:
        lines += ["", "## Scan notes", ""]
        for name, error in errors:
            lines.append(f"- **{name.upper()}**: {_safe_md(error)}")
    lines += ["", "*UNKNOWN is not HIGH. Counts are tool findings, not verified unique vulnerabilities.*", ""]
    return "\n".join(lines)


def _write_report(out: Path, report: dict[str, Any], summary: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(summary, encoding="utf-8")


def run_scan(opts: argparse.Namespace) -> int:
    root = Path(opts.target).expanduser().resolve()
    if not root.is_dir():
        log(f"[ERROR] Directory not found: {root}")
        return 2
    chosen = [key for key in SCAN_KEYS if key in opts.scanners.split(",")]
    if not chosen or set(opts.scanners.split(",")) - set(SCAN_KEYS):
        log("[ERROR] --scanners must be a comma-separated subset of sast,sca,secret,iac")
        return 2
    policy = selected_policy(load_policy(opts.policy), opts)
    log(f"Scanning: {root}")
    log(f"Scanners: {', '.join(chosen)} (max parallel jobs: {opts.jobs})")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(opts.jobs, len(chosen))) as executor:
        futures = {executor.submit(scan_one, name, root, opts): name for name in chosen}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                item = future.result()
            except Exception as exc:
                item = {"status": "ERROR", "count": 0, "findings": [], "error": shorten(exc), "elapsed_seconds": 0, "exit_code": None}
            item["findings"] = apply_policy(item["findings"], policy)
            results[name] = item
            log(f"[{item['status']}] {name.upper():7s} findings={item['count']} duration={item['elapsed_seconds']}s" + (f" ({item['error']})" if item.get("error") else ""))
    errors = any(item["status"] == "ERROR" for item in results.values())
    all_skipped = all(item["status"] == "SKIPPED" for item in results.values())
    candidates = [f for item in results.values() for f in item["findings"]]
    result, blocked, reviews = gate_result(candidates, policy)
    outcome = "ERROR" if errors or all_skipped else result
    by_severity = Counter(f.get("severity") for f in candidates)
    report = {
        "schema_version": 2, "report_type": "scan", "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": str(root), "status": outcome,
        "policy": policy, "scan_profile": {"semgrep_config": opts.semgrep_config, "secrets_mode": opts.secrets_mode},
        "total_findings": len(candidates), "blocking_findings": blocked, "review_findings": reviews,
        "by_severity": {key: by_severity.get(key, 0) for key in SEVERITIES},
        "scans": {key: results[key] for key in chosen},
    }
    out_dir = Path(opts.out).expanduser().resolve()
    _write_report(out_dir, report, make_summary(report))
    log(f"Overall: {outcome}; total findings={len(candidates)}; blocking={blocked}; review={reviews}")
    log(f"Reports: {out_dir / 'report.json'} and {out_dir / 'summary.md'}")
    return EXIT_CODES[outcome]


def structural_key(f: dict[str, Any]) -> tuple[str, ...]:
    # Do not use line numbers: insertions above a finding should not make it 'new'.
    # IaC often reports root-relative paths starting with '/', so normalize both forms.
    # A version change in an SCA dependency is significant and should count as introduced.
    return tuple(str(f.get(k) or "").replace("\\", "/").lstrip("/") if k == "file"
                 else str(f.get(k) or "") for k in ("scanner", "rule_id", "file", "package", "version", "resource"))


def compare_findings(baseline: list[dict[str, Any]], current: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Multiset comparison with optional stable Semgrep fingerprints and line-shift tolerance.

    Weak scanner identities compare rule+file+resource+package/version counts. Same-rule
    same-file replacements with equal counts cannot be distinguished unless a stable
    fingerprint is available; report this documented limitation, not certainty.
    """
    groups: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for i, finding in enumerate(baseline):
        groups[structural_key(finding)].append(i)
    matched: set[int] = set()
    introduced: list[dict[str, Any]] = []
    unchanged = 0
    for finding in current:
        candidates = [i for i in groups.get(structural_key(finding), []) if i not in matched]
        fingerprint = finding.get("fingerprint")
        match_id = next((i for i in candidates if fingerprint and baseline[i].get("fingerprint") == fingerprint), None)
        if match_id is None:
            # Weaker fallback only when one side lacks a fingerprint.
            match_id = next((i for i in candidates if not fingerprint or not baseline[i].get("fingerprint")), None)
        if match_id is None:
            introduced.append({**finding, "change_type": "NEW"})
            continue
        matched.add(match_id)
        old = baseline[match_id]
        old_sev, new_sev = old.get("severity", "UNKNOWN"), finding.get("severity", "UNKNOWN")
        # Reclassifications from lower/unknown severity to higher severity are gate candidates.
        if SCORES.get(new_sev, -1) > SCORES.get(old_sev, -1):
            introduced.append({**finding, "change_type": "ESCALATED", "previous_severity": old_sev})
        elif new_sev == "UNKNOWN" and old_sev != "UNKNOWN":
            introduced.append({**finding, "change_type": "RECLASSIFIED", "previous_severity": old_sev})
        else:
            unchanged += 1
    resolved = [f for i, f in enumerate(baseline) if i not in matched]
    return introduced, resolved, unchanged


def _load_scan_report(location: str) -> dict[str, Any]:
    report = json.loads(Path(location).expanduser().read_text(encoding="utf-8"))
    if not isinstance(report, dict) or not isinstance(report.get("scans"), dict):
        raise ValueError(f"Not a valid scan report: {location}")
    if report.get("report_type", "scan") != "scan":
        raise ValueError(f"Expected scan report, not comparison: {location}")
    return report


def compare_reports(baseline: dict[str, Any], head: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Fail closed when either scanner result is invalid or incomplete."""
    errors: list[str] = []
    if baseline.get("scan_profile") != head.get("scan_profile"):
        errors.append("Baseline/head scan profiles differ (ruleset or secret scan mode)")
    base_scans, head_scans = baseline.get("scans") or {}, head.get("scans") or {}
    if set(base_scans) != set(head_scans):
        errors.append("Scanner sets differ between baseline and head")
    if not head_scans:
        errors.append("No scanners present in comparison")
    if baseline.get("status") == "ERROR" or head.get("status") == "ERROR":
        errors.append("Baseline or head scan has overall ERROR status")
    if head_scans and all(item.get("status") == "SKIPPED" for item in head_scans.values()):
        errors.append("All candidate scanners skipped; scan coverage cannot be trusted")
    if base_scans and all(item.get("status") == "SKIPPED" for item in base_scans.values()):
        errors.append("All baseline scanners skipped; comparison is not meaningful")
    new_findings: list[dict[str, Any]] = []
    resolved_findings: list[dict[str, Any]] = []
    per_scanner = {}
    for key in SCAN_KEYS:
        if key not in base_scans or key not in head_scans:
            continue
        base, newer = base_scans[key], head_scans[key]
        bs, hs = base.get("status"), newer.get("status")
        if bs not in {"COMPLETE", "SKIPPED"} or hs not in {"COMPLETE", "SKIPPED"}:
            errors.append(f"{key}: invalid baseline/head status ({bs} / {hs})")
            continue
        if bs == "COMPLETE" and hs == "SKIPPED":
            errors.append(f"{key}: scanner changed from COMPLETE to SKIPPED; cannot safely approve")
            continue
        if bs == "SKIPPED" and base.get("findings"):
            errors.append(f"{key}: skipped baseline unexpectedly contains findings")
            continue
        if hs == "SKIPPED" and newer.get("findings"):
            errors.append(f"{key}: skipped head unexpectedly contains findings")
            continue
        base_f = apply_policy(base.get("findings") or [], policy)
        head_f = apply_policy(newer.get("findings") or [], policy)
        new_f, resolved_f, unchanged = compare_findings(base_f, head_f)
        new_findings.extend(new_f)
        resolved_findings.extend(resolved_f)
        per_scanner[key] = {"baseline": len(base_f), "head": len(head_f),
                            "new_or_escalated": len(new_f), "resolved": len(resolved_f), "unchanged": unchanged,
                            "status": f"{bs}->{hs}"}
    state, blocked, reviews = gate_result(new_findings, policy)
    if errors:
        state = "ERROR"
    return {
        "schema_version": 2, "report_type": "comparison", "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": state, "base_target": baseline.get("target"), "head_target": head.get("target"),
        "policy": policy, "new_or_escalated_findings": new_findings, "resolved_findings": resolved_findings,
        "new_count": len(new_findings), "resolved_count": len(resolved_findings),
        "existing_count": sum(v["unchanged"] for v in per_scanner.values()),
        "blocking_findings": blocked, "review_findings": reviews,
        "by_scanner": per_scanner, "errors": errors,
        "matching_notes": "Line numbers ignored. Weak identity uses scanner/rule/file/resource/dependency/version and occurrence count. Semgrep fingerprint is used when available; replacements with equal weak identity may be missed.",
    }


def make_comparison_summary(report: dict[str, Any]) -> str:
    policy = report["policy"]
    lines = ["# Pull Request Security Gate", "",
             f"- Decision: **{report['status']}**", f"- Policy threshold: **{policy['fail_on']}**; unknown: **{policy['unknown_behavior']}**",
             f"- New or escalated findings: **{report['new_count']}**",
             f"- Existing findings (not gated): **{report['existing_count']}**",
             f"- Resolved findings: **{report['resolved_count']}**",
             f"- Blocking: **{report['blocking_findings']}**; needs review: **{report['review_findings']}**", "",
             "| Scanner | Baseline | PR | New/escalated | Resolved | Unchanged |",
             "|---|---:|---:|---:|---:|---:|"]
    for key in SCAN_KEYS:
        if key in report["by_scanner"]:
            s = report["by_scanner"][key]
            lines.append(f"| {key.upper()} | {s['baseline']} | {s['head']} | {s['new_or_escalated']} | {s['resolved']} | {s['unchanged']} |")
    if report["errors"]:
        lines += ["", "## Comparison errors", ""] + [f"- {_safe_md(e)}" for e in report["errors"]]
    lines += ["", "## New or escalated findings (first 100)", "",
              "| Change | Scanner | Severity | Rule | Location |", "|---|---|---|---|---|"]
    sorted_findings = sorted(report["new_or_escalated_findings"], key=lambda f: SCORES.get(f.get("severity"), 3), reverse=True)
    for f in sorted_findings[:100]:
        loc = str(f.get("file", "")) + (f":{f['line']}" if f.get("line") is not None else "")
        lines.append(f"| {_safe_md(f['change_type'])} | {_safe_md(f.get('scanner'))} | {_safe_md(f.get('severity'))} | {_safe_md(f.get('rule_id'))} | {_safe_md(loc)} |")
    if not sorted_findings:
        lines.append("| - | - | - | - | No newly introduced findings |")
    lines += ["", "*Only new/escalated findings affect the PR gate; scanner errors or untrusted baseline fail closed. See README for identity limitations.*", ""]
    return "\n".join(lines)


def run_compare(opts: argparse.Namespace) -> int:
    policy = selected_policy(load_policy(opts.policy), opts)
    try:
        base = _load_scan_report(opts.baseline)
        head = _load_scan_report(opts.current)
        report = compare_reports(base, head, policy)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        log(f"[ERROR] Cannot compare reports: {shorten(exc, 400)}")
        return 2
    output = Path(opts.out).expanduser().resolve()
    _write_report(output, report, make_comparison_summary(report))
    log(f"PR Gate: {report['status']}; new/escalated={report['new_count']}; existing={report['existing_count']}; resolved={report['resolved_count']}; block={report['blocking_findings']}; review={report['review_findings']}")
    for err in report["errors"]:
        log(f"[ERROR] {err}")
    log(f"Reports: {output / 'report.json'} and {output / 'summary.md'}")
    return EXIT_CODES[report["status"]]


def self_test() -> int:
    """Offline checks of the normalizers and gate (not actual scanner execution)."""
    root = APP_DIR
    try:
        sem = parse_semgrep({"results": [{"check_id": "rule.sqli", "path": "app.py", "start": {"line": 5}, "extra": {"message": "SQL injection", "severity": "ERROR"}}]}, root)
        assert len(sem) == 1 and sem[0]["severity"] == "HIGH"
        osv = parse_osv({"results": [{"source": {"path": "requirements.txt"}, "packages": [{"package": {"name": "example", "version": "1"}, "vulnerabilities": [{"id": "CVE-TEST-1", "severity": [{"score": "9.8"}]}, {"id": "GHSA-TEST-1", "aliases": ["CVE-TEST-1"]}], "groups": [{"ids": ["CVE-TEST-1", "GHSA-TEST-1"]}]}]}]}, root)
        assert len(osv) == 1 and osv[0]["severity"] == "CRITICAL"
        secret = parse_gitleaks([{"RuleID": "test-secret", "Description": "fake key", "File": "config.env", "StartLine": 7, "Secret": "do-not-leak", "Match": "do-not-leak", "Line": "do-not-leak"}], root)
        assert len(secret) == 1 and "do-not-leak" not in json.dumps(secret)
        iac = parse_checkov([{"check_type": "terraform", "results": {"failed_checks": [{"check_id": "CKV_TEST_1", "check_name": "Public endpoint", "file_path": "main.tf", "file_line_range": [2, 6], "severity": None}]}}], root)
        assert len(iac) == 1 and iac[0]["severity"] == "UNKNOWN"
        policy = load_policy(None)
        assert gate_result(apply_policy(iac, policy), policy)[0] in {"REVIEW", "FAIL"}
        assert gate_result(apply_policy(sem, policy), policy)[0] == "FAIL"
        assert gate_result(apply_policy(sem, {**policy, "fail_on": "CRITICAL"}), {**policy, "fail_on": "CRITICAL"})[0] == "PASS"
        fake_process = subprocess.CompletedProcess(args=["semgrep"], returncode=2, stdout="", stderr="ERROR: Cannot create auto config when metrics are off")
        explanation = semgrep_failure_hint(fake_process, "auto")
        assert "p/default" in explanation and "exit=2" in explanation
        log("[PASS] Offline self-test: 4 parsers, secret redaction, CVSS, severity policy, Semgrep diagnostic")
        log("Note: This does NOT run the installed scanners. Run 'doctor' and 'scan' for real validation.")
        return 0
    except (AssertionError, Exception) as exc:
        log(f"[ERROR] Self-test failed: {shorten(exc)}")
        return 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevSecOps starter v1.2 - PR baseline and policy-aware Security Gate")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Verify local scanner installations")
    sub.add_parser("self-test", help="Run small offline parser and policy checks")
    install = sub.add_parser("setup-tools", help="Install checksum-verified Gitleaks/OSV-Scanner (Linux)")
    install.add_argument("--osv-version", default=DEFAULT_TAGS["osv-scanner"])
    install.add_argument("--gitleaks-version", default=DEFAULT_TAGS["gitleaks"])
    install.add_argument("--force", action="store_true")

    def policy_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--policy", help="Trusted local security-policy.json (default: beside devsecops.py)")
        p.add_argument("--fail-on", choices=("low", "medium", "high", "critical", "none"), default=None,
                       help="Override fail_on from policy. 'none' for collection-only scans.")
        p.add_argument("--unknown-policy", choices=("block", "review", "warn"), default=None,
                       help="Override handling of unmapped UNKNOWN severity findings")
        p.add_argument("--allow-unknown", action="store_true", help="Legacy alias: --unknown-policy warn")

    scan = sub.add_parser("scan", help="Run 4 security scanners and export reports")
    scan.add_argument("--target", default=".")
    scan.add_argument("--out", default="reports")
    scan.add_argument("--scanners", default="sast,sca,secret,iac")
    scan.add_argument("--secrets-mode", choices=("dir", "git"), default="dir")
    scan.add_argument("--semgrep-config", default="p/default")
    scan.add_argument("--timeout", type=int, default=600)
    scan.add_argument("--jobs", type=int, default=2, choices=(1,2,3,4))
    policy_options(scan)

    compare = sub.add_parser("compare", help="Compare clean baseline/main and PR reports; gate only new findings")
    compare.add_argument("--baseline", "--base", required=True, dest="baseline")
    compare.add_argument("--current", "--head", required=True, dest="current")
    compare.add_argument("--out", default="reports/pr-gate")
    policy_options(compare)
    return parser.parse_args()


def main() -> int:
    opts = parse_args()
    try:
        if opts.command == "self-test":
            return self_test()
        if opts.command == "doctor":
            return doctor()
        if opts.command == "setup-tools":
            return setup_tools(opts.osv_version, opts.gitleaks_version, opts.force)
        if opts.command == "scan":
            return run_scan(opts)
        if opts.command == "compare":
            return run_compare(opts)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        log(f"[ERROR] {shorten(exc, 400)}")
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
