#!/usr/bin/env python3
"""Milestone 7: private GHCR image -> isolated Docker startup -> internal HTTP smoke test.

No host port is published and the test container has --network=none. A small,
shareable diagnostic report is generated even when a step fails. Stdout/stderr
of the intentionally vulnerable app are NOT uploaded or copied into reports.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

IMAGE_RE = re.compile(r"^ghcr\.io/crabs536/wrongsecrets-devsecops-lab:sha-([0-9a-f]{40})$")
HEALTH_RE = re.compile(r"^/[A-Za-z0-9/_~.\-%?=&]*$")
EXCEPTION_RE = re.compile(r"\b(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Exception|Error)\b")
REPORT_SCHEMA = "devsecops-m7-v1"

HINTS = {
    "CONFIG": "Image must be ghcr.io/crabs536/wrongsecrets-devsecops-lab:sha-<40 hex>. Check release SHA/variable.",
    "DOCKER_CHECK": "Docker daemon is unavailable. Run `docker info`, check group permissions and Docker service.",
    "GHCR_AUTH": "Check packages:read for GITHUB_TOKEN, GHCR package access for this repository, and that the package is Private.",
    "IMAGE_PULL": "Check image tag exists in GHCR and package read permissions; increase --pull-timeout if network is slow.",
    "IMAGE_INSPECT": "Docker pulled an image but cannot inspect it. Check Docker storage and image reference.",
    "CONTAINER_START": "See container exit status and exception class names in report.json. Confirm SPRING_PROFILES_ACTIVE=local,without-vault.",
    "ISOLATION": "Container is not fully isolated (network, ports, privileged mode, or mounts). Do not publish a host port.",
    "HEALTH_CHECK": "Container did not serve successful HTTP inside its own loopback before timeout. Inspect Spring profile, startup/errors, and health path.",
    "PROBE_TOOL_MISSING": "BusyBox wget/wget missing from image. Choose an image with an internal HTTP probe or add one; no port should be exposed.",
    "CLEANUP": "Cannot remove test container. Inspect `docker ps -a` and remove ONLY the M7 container by its reported name.",
    "UNEXPECTED": "Unexpected error; see report.json and sanitized diagnostics. Do not paste raw secrets or raw application logs.",
}


class StageFailure(Exception):
    def __init__(self, stage: str, code: str, message: str, exit_code: int = 1):
        super().__init__(message)
        self.stage = stage
        self.code = code
        self.exit_code = exit_code


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def validate_image(image: str) -> str:
    if not IMAGE_RE.fullmatch(image):
        raise StageFailure("VALIDATE", "CONFIG", f"Invalid image reference: {image!r}", 2)
    return image


def validate_health_path(path: str) -> str:
    if not HEALTH_RE.fullmatch(path) or ".." in path or len(path) > 120:
        raise StageFailure("VALIDATE", "CONFIG", "Invalid health path (use a short relative URL such as /).", 2)
    return path


def redact(s: str) -> str:
    # The script never records the authentication token or raw Docker logs.
    s = re.sub(r"(?i)Bearer\s+\S+", "Bearer [REDACTED]", s)
    s = re.sub(r"(?i)((?:password|passwd|secret|token|apikey|api_key|authorization|credential)\s*[=:]\s*)\S+", r"\1[REDACTED]", s)
    s = re.sub(r"(?i)gh[pousr]_[A-Za-z0-9_]{15,}", "[REDACTED_GITHUB_TOKEN]", s)
    return s[-1200:]


def exception_names(log: str) -> List[str]:
    # Extract only Java exception class names, NEVER upload raw app logs.
    return sorted(set(EXCEPTION_RE.findall(log)))[:25]


def shell_run(argv: List[str], timeout: int, env: Optional[Dict[str, str]] = None,
              input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=input_text, text=True, capture_output=True,
                          env=env, timeout=timeout, check=False)


class Smoke:
    def __init__(self, args: argparse.Namespace, command=shell_run):
        self.args = args
        self.command = command
        self.report_dir = Path(args.report_dir)
        self.image = args.image
        self.name = "m7-smoke-" + secrets.token_hex(5)
        self.container_created = False
        self.docker_ready = False
        self.image_id: Optional[str] = None
        self.image_digest: Optional[str] = None
        self.probe_attempts = 0
        self.last_probe_status = "not_started"
        self.exceptions: List[str] = []
        self.container_state: Dict[str, Any] = {}
        self.stages: List[Dict[str, Any]] = []
        self.error: Optional[Dict[str, Any]] = None
        self.success = False
        self.started_at = utc_now()
        self.cleanup_attempted = False
        self.cleanup_succeeded = False
        self.docker_config_dir: Optional[tempfile.TemporaryDirectory] = None

    def exec(self, argv: List[str], timeout: int, input_text=None, env=None):
        try:
            return self.command(argv, timeout=timeout, input_text=input_text, env=env)
        except subprocess.TimeoutExpired:
            raise StageFailure(self.current_stage, self.timeout_code(),
                               f"Command timed out after {timeout}s: {argv[0]} {argv[1] if len(argv)>1 else ''}")
        except FileNotFoundError:
            raise StageFailure(self.current_stage, "DOCKER_CHECK", f"Command not found: {argv[0]}")

    def timeout_code(self) -> str:
        return {"PULL": "IMAGE_PULL", "HEALTH": "HEALTH_CHECK", "AUTH": "GHCR_AUTH"}.get(self.current_stage, "UNEXPECTED")

    def stage(self, name: str, func):
        self.current_stage = name
        begin = time.monotonic()
        print(f"[M7][{name}][RUNNING]", flush=True)
        try:
            result = func()
        except StageFailure as exc:
            self.stages.append({"stage": name, "status": "FAIL", "seconds": round(time.monotonic() - begin, 2),
                                "error_code": exc.code})
            print(f"[M7][{name}][FAIL:{exc.code}] {redact(str(exc))}", flush=True)
            raise
        except Exception as exc:
            self.stages.append({"stage": name, "status": "FAIL", "seconds": round(time.monotonic() - begin, 2),
                                "error_code": "UNEXPECTED"})
            raise StageFailure(name, "UNEXPECTED", f"{type(exc).__name__}: {redact(str(exc))}") from exc
        self.stages.append({"stage": name, "status": "PASS", "seconds": round(time.monotonic() - begin, 2)})
        print(f"[M7][{name}][PASS]", flush=True)
        return result

    def validate(self):
        validate_image(self.image)
        validate_health_path(self.args.health_path)
        if not (1 <= self.args.pull_timeout <= 7200 and 10 <= self.args.health_timeout <= 3600):
            raise StageFailure("VALIDATE", "CONFIG", "Timeouts outside supported safe range", 2)
        if self.args.interval < 1 or self.args.interval > 60:
            raise StageFailure("VALIDATE", "CONFIG", "Invalid health retry interval", 2)

    def doctor(self):
        if not shutil.which("docker"):
            raise StageFailure("DOCKER", "DOCKER_CHECK", "docker CLI is not installed.")
        cp = self.exec(["docker", "info", "--format", "{{.ServerVersion}}"], 30)
        if cp.returncode != 0:
            raise StageFailure("DOCKER", "DOCKER_CHECK", redact(cp.stderr or cp.stdout or "docker info failed"))
        self.docker_ready = True

    def authenticate(self):
        token = os.environ.get("GHCR_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise StageFailure("AUTH", "GHCR_AUTH", "Missing GHCR_TOKEN or GITHUB_TOKEN environment variable.", 3)
        self.docker_config_dir = tempfile.TemporaryDirectory(prefix="m7-ghcr-auth-")
        docker_env = dict(os.environ)
        docker_env["DOCKER_CONFIG"] = self.docker_config_dir.name
        # Avoid echoing credentials. docker login writes into a temporary Docker config.
        username = os.environ.get("GHCR_USERNAME") or os.environ.get("GITHUB_ACTOR") or "Crabs536"
        cp = self.exec(["docker", "login", "ghcr.io", "-u", username, "--password-stdin"],
                       60, input_text=token + "\n", env=docker_env)
        if cp.returncode != 0:
            raise StageFailure("AUTH", "GHCR_AUTH", redact(cp.stderr or "GHCR login failed"), 3)

    def pull(self):
        assert self.docker_config_dir is not None
        docker_env = dict(os.environ)
        docker_env["DOCKER_CONFIG"] = self.docker_config_dir.name
        cp = self.exec(["docker", "pull", self.image], self.args.pull_timeout, env=docker_env)
        if cp.returncode != 0:
            raise StageFailure("PULL", "IMAGE_PULL", redact(cp.stderr or cp.stdout or "docker pull failed"), 4)

    def inspect_image(self):
        cp = self.exec(["docker", "image", "inspect", self.image], 30)
        if cp.returncode != 0:
            raise StageFailure("IMAGE", "IMAGE_INSPECT", redact(cp.stderr), 4)
        try:
            d = json.loads(cp.stdout)[0]
            self.image_id = d["Id"]
            digests = d.get("RepoDigests") or []
            self.image_digest = next((x for x in digests if x.startswith("ghcr.io/crabs536/wrongsecrets-devsecops-lab@")), None)
            if not self.image_id.startswith("sha256:"):
                raise ValueError("Image ID missing")
        except (IndexError, ValueError, KeyError, TypeError) as exc:
            raise StageFailure("IMAGE", "IMAGE_INSPECT", f"Docker inspect returned invalid image metadata: {exc}", 4)

    def start_container(self):
        assert self.image_id is not None
        # No -p, --network none: no inbound or outbound network. HTTP probed only inside container.
        cmd = ["docker", "run", "-d", "--name", self.name, "--network", "none",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "512", "--memory", "3g", "--cpus", "2",
               "--restart", "no", "--pull", "never",
               "-e", "SPRING_PROFILES_ACTIVE=local,without-vault", "-e", "K8S_ENV=docker",
               "-e", "SPRINGDOC_UI=false", "-e", "SPRINGDOC_DOC=false",
               self.image_id]
        cp = self.exec(cmd, 120)
        if cp.returncode != 0:
            raise StageFailure("START", "CONTAINER_START", redact(cp.stderr or cp.stdout or "docker run failed"), 5)
        self.container_created = True

    def inspect_container(self) -> Dict[str, Any]:
        cp = self.exec(["docker", "inspect", self.name], 20)
        if cp.returncode != 0:
            raise StageFailure(self.current_stage, "CONTAINER_START", redact(cp.stderr), 5)
        try:
            d = json.loads(cp.stdout)[0]
            state = d["State"]
            self.container_state = {
                "status": state.get("Status"), "running": bool(state.get("Running")),
                "exit_code": state.get("ExitCode"), "oom_killed": bool(state.get("OOMKilled"))
            }
            return d
        except (ValueError, IndexError, TypeError, KeyError) as exc:
            raise StageFailure(self.current_stage, "CONTAINER_START", f"Invalid container inspect JSON: {exc}", 5)

    def isolation(self):
        d = self.inspect_container()
        config = d.get("HostConfig") or {}
        if (config.get("NetworkMode") != "none"
                or bool(config.get("PortBindings"))
                or bool(config.get("Privileged"))
                or bool(d.get("Mounts"))):
            raise StageFailure("ISOLATION", "ISOLATION", "Unexpected network / port / privileged / mount configuration", 5)
        if not self.container_state.get("running"):
            raise StageFailure("ISOLATION", "CONTAINER_START",
                               f"Container stopped on startup: exit_code={self.container_state.get('exit_code')} OOM={self.container_state.get('oom_killed')}", 5)

    def check_health(self):
        endpoint = "http://127.0.0.1:8080" + self.args.health_path
        # sh -c with a positional URL (no shell injection). Alpine normally has BusyBox wget.
        script = ("if command -v wget >/dev/null 2>&1; then "
                  "wget -q -T 5 -O /dev/null \"$1\"; "
                  "elif command -v busybox >/dev/null 2>&1; then "
                  "busybox wget -q -T 5 -O /dev/null \"$1\"; "
                  "else exit 127; fi")
        deadline = time.monotonic() + self.args.health_timeout
        while True:
            self.probe_attempts += 1
            d = self.inspect_container()
            if not self.container_state.get("running"):
                raise StageFailure("HEALTH", "CONTAINER_START",
                                   f"App process exited before ready: exit_code={self.container_state.get('exit_code')}", 5)
            cp = self.exec(["docker", "exec", self.name, "sh", "-c", script, "m7-probe", endpoint], 15)
            if cp.returncode == 0:
                self.last_probe_status = "http_ok"
                return
            if cp.returncode == 127:
                self.last_probe_status = "missing_http_tool"
                raise StageFailure("HEALTH", "PROBE_TOOL_MISSING", "Cannot find wget/BusyBox inside image.", 6)
            self.last_probe_status = f"wget_exit_{cp.returncode}"
            if time.monotonic() >= deadline:
                raise StageFailure("HEALTH", "HEALTH_CHECK",
                                   f"No successful HTTP within {self.args.health_timeout}s; "
                                   f"attempts={self.probe_attempts}, last={self.last_probe_status}", 6)
            if self.probe_attempts == 1 or self.probe_attempts % 6 == 0:
                print(f"[M7][HEALTH][WAIT] attempt={self.probe_attempts}, retrying in {self.args.interval}s", flush=True)
            time.sleep(min(self.args.interval, max(0, deadline - time.monotonic())))

    def inspect_exception_names(self):
        if not self.container_created:
            return
        # DO NOT persist or echo raw logs. Vulnerable app may log credentials.
        try:
            cp = self.exec(["docker", "logs", "--tail", "250", self.name], 20)
            self.exceptions = exception_names((cp.stdout or "") + "\n" + (cp.stderr or ""))
        except StageFailure:
            pass

    def cleanup(self):
        self.current_stage = "CLEANUP"
        self.cleanup_attempted = True
        if self.container_created:
            try:
                cp = self.exec(["docker", "rm", "-f", self.name], 50)
                self.cleanup_succeeded = cp.returncode == 0
            except StageFailure:
                self.cleanup_succeeded = False
        else:
            self.cleanup_succeeded = True
        if self.docker_config_dir:
            self.docker_config_dir.cleanup()
        self.stages.append({"stage": "CLEANUP", "status": "PASS" if self.cleanup_succeeded else "FAIL"})
        print(f"[M7][CLEANUP][{'PASS' if self.cleanup_succeeded else 'FAIL'}]", flush=True)
        if not self.cleanup_succeeded and self.error is None:
            self.error = {"stage": "CLEANUP", "code": "CLEANUP", "message": "Container cleanup failed", "hint": HINTS["CLEANUP"]}
            self.success = False

    def write_reports(self):
        self.report_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "schema": REPORT_SCHEMA, "result": "PASS" if self.success and self.cleanup_succeeded else "FAIL",
            "started_at": self.started_at, "finished_at": utc_now(),
            "image": self.image, "image_id": self.image_id, "image_digest": self.image_digest,
            "container_name": self.name, "container_state": self.container_state,
            "network_mode": "none", "published_ports": [], "probe_path": self.args.health_path,
            "probe_attempts": self.probe_attempts, "last_probe_status": self.last_probe_status,
            "exception_class_names": self.exceptions, "steps": self.stages,
            "cleanup_ok": self.cleanup_succeeded, "error": self.error,
            "security_note": "No raw Docker app logs or GHCR credentials are stored. Review even sanitized reports before sharing."
        }
        (self.report_dir / "report.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        decision = data["result"]
        lines = [f"# Milestone 7 — Private GHCR Staging Smoke: {decision}", "",
                 f"- Image: `{self.image}`", f"- Image digest: `{self.image_digest or 'not available'}`",
                 "- Isolation: Docker `--network none`, **no published host ports**",
                 f"- Internal HTTP test: `http://127.0.0.1:8080{self.args.health_path}`",
                 f"- Probe attempts: **{self.probe_attempts}**",
                 f"- Cleanup: **{'PASS' if self.cleanup_succeeded else 'FAIL'}**", "",
                 "## Step results", "", "| Step | Status | Seconds |", "|---|---|---:|"]
        for s in self.stages:
            lines.append(f"| {s['stage']} | {s['status']} | {s.get('seconds', '-')} |")
        if self.error:
            lines.extend(["", "## Failure diagnosis", "",
                          f"- Failed step: **{self.error['stage']}**",
                          f"- Error code: **{self.error['code']}**",
                          f"- Detail: {self.error['message']}",
                          f"- Suggested fix: {self.error['hint']}"])
        if self.exceptions:
            lines.extend(["", "## Exception class names (not raw logs)", "",
                          ", ".join(f"`{s}`" for s in self.exceptions)])
        lines.extend(["", "> This is a startup smoke test, **not a security clearance**. "
                      "WrongSecrets contains intentionally vulnerable code. Raw application logs are deliberately omitted.", ""])
        (self.report_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
        print(f"[M7][RESULT] {decision} | report={self.report_dir / 'report.json'} | summary={self.report_dir / 'summary.md'}", flush=True)

    def run(self) -> int:
        try:
            self.stage("VALIDATE", self.validate)
            self.stage("DOCKER", self.doctor)
            self.stage("AUTH", self.authenticate)
            self.stage("PULL", self.pull)
            self.stage("IMAGE", self.inspect_image)
            self.stage("START", self.start_container)
            self.stage("ISOLATION", self.isolation)
            self.stage("HEALTH", self.check_health)
            self.success = True
        except StageFailure as exc:
            self.error = {"stage": exc.stage, "code": exc.code, "message": redact(str(exc)),
                          "hint": HINTS.get(exc.code, HINTS["UNEXPECTED"])}
            self.inspect_exception_names()
        finally:
            self.cleanup()
            self.write_reports()
        if not self.success or not self.cleanup_succeeded:
            return 1
        return 0


def self_test() -> int:
    assert validate_image("ghcr.io/crabs536/wrongsecrets-devsecops-lab:sha-" + "a" * 40)
    for v in ["ghcr.io/evil/test:latest", "ghcr.io/crabs536/wrongsecrets-devsecops-lab:latest"]:
        try:
            validate_image(v)
            raise AssertionError("Invalid image accepted")
        except StageFailure:
            pass
    assert validate_health_path("/") == "/"
    assert exception_names("foo java.lang.IllegalStateException data") == ["java.lang.IllegalStateException"]
    assert "example" not in redact("authorization=example")
    print("[M7][SELF-TEST][PASS] reference validation, path, exception names, redaction")
    return 0


def doctor_command() -> int:
    print("[M7][DOCTOR] Checking Docker installation/daemon")
    try:
        cp = shell_run(["docker", "info", "--format", "{{.ServerVersion}}"], 30)
        if cp.returncode == 0:
            print("[M7][DOCTOR][PASS] Docker daemon:", cp.stdout.strip())
            return 0
        print("[M7][DOCTOR][FAIL]", redact(cp.stderr))
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("[M7][DOCTOR][FAIL]", redact(str(exc)))
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Private GHCR isolated deployment smoke test")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")
    sub.add_parser("doctor")
    run = sub.add_parser("run")
    run.add_argument("--image", required=True)
    run.add_argument("--report-dir", default="m7-reports")
    run.add_argument("--health-path", default="/")
    run.add_argument("--pull-timeout", type=int, default=1800, help="seconds; default 30 minutes")
    run.add_argument("--health-timeout", type=int, default=600, help="seconds; default 10 minutes")
    run.add_argument("--interval", type=int, default=8)
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return self_test()
    if args.command == "doctor":
        return doctor_command()
    return Smoke(args).run()


if __name__ == "__main__":
    sys.exit(main())
