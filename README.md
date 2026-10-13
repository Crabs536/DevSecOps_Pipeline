# DevSecOps_Pipeline

## Overview

DevSecOps Pipeline v1.2 is a Python-based security scanning
orchestrator integrating:

- Semgrep: SAST
- OSV-Scanner: SCA
- Gitleaks: Secret Detection
- Checkov: Infrastructure as Code Security

Features:
- Unified JSON and Markdown reports
- Severity Mapping
- Baseline Comparison
- Pull Request Security Gate
- PASS / FAIL / REVIEW / ERROR decisions

## Local Setup

Requires Python 3.11+ and Git.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python devsecops.py setup-tools
python devsecops.py doctor
python devsecops.py self-test
