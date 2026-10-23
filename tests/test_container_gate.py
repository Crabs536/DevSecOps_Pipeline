import unittest
import importlib.util
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "container_gate.py"
spec = importlib.util.spec_from_file_location("container_gate", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def payload(*vulns):
    return {"SchemaVersion": 2, "Results": [] if not vulns else [{
        "Target": "Alpine 3.x (alpine 3.x)", "Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": list(vulns)
    }]}


def vuln(vid="CVE-2026-DEMO", sev="HIGH", version="1.0", pkg="busybox"):
    return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": version, "Severity": sev}


class TestContainerGate(unittest.TestCase):
    def cmp(self, base, pr, policy=None):
        return mod.evaluate(mod.compare(mod.parse_trivy(base), mod.parse_trivy(pr)),
                            policy or {"fail_on": "HIGH", "unknown": "review"})

    def test_identical_baseline(self):
        r = self.cmp(payload(vuln()), payload(vuln()))
        self.assertEqual((r["decision"], r["existing"], len(r["new_or_escalated"])), ("PASS", 1, 0))

    def test_new_high_blocks(self):
        r = self.cmp(payload(), payload(vuln()))
        self.assertEqual((r["decision"], r["blocking"]), ("FAIL", 1))

    def test_new_critical_blocks(self):
        r = self.cmp(payload(), payload(vuln(sev="CRITICAL")))
        self.assertEqual(r["decision"], "FAIL")

    def test_medium_allowed(self):
        self.assertEqual(self.cmp(payload(), payload(vuln(sev="MEDIUM")))["decision"], "PASS")

    def test_new_unknown_requires_review(self):
        r = self.cmp(payload(), payload(vuln(sev="UNKNOWN")))
        self.assertEqual((r["decision"], r["needs_review"]), ("REVIEW", 1))

    def test_unknown_block_policy(self):
        r = self.cmp(payload(), payload(vuln(sev="UNKNOWN")), {"fail_on": "HIGH", "unknown": "block"})
        self.assertEqual(r["decision"], "FAIL")

    def test_existing_upgrade_same_cve_not_new(self):
        r = self.cmp(payload(vuln(version="1.0")), payload(vuln(version="1.1")))
        self.assertEqual((r["decision"], r["existing"]), ("PASS", 1))

    def test_existing_severity_escalation_blocks(self):
        r = self.cmp(payload(vuln(sev="MEDIUM")), payload(vuln(sev="HIGH")))
        self.assertEqual(r["new_or_escalated"][0]["change"], "ESCALATED")
        self.assertEqual(r["decision"], "FAIL")

    def test_resolved(self):
        r = self.cmp(payload(vuln()), payload())
        self.assertEqual((r["decision"], r["resolved"]), ("PASS", 1))

    def test_same_advisory_another_pkg_blocks(self):
        r = self.cmp(payload(vuln(pkg="busybox")), payload(vuln(pkg="busybox"), vuln(pkg="openssl")))
        self.assertEqual((r["decision"], r["blocking"]), ("FAIL", 1))

    def test_duplicate_same_identity_no_undercount(self):
        r = self.cmp(payload(vuln()), payload(vuln(), vuln()))
        self.assertEqual((r["existing"], r["blocking"]), (1, 1))

    def test_invalid_no_results(self):
        with self.assertRaises(ValueError):
            mod.parse_trivy({"SchemaVersion": 2})

    def test_invalid_missing_schema(self):
        with self.assertRaises(ValueError):
            mod.parse_trivy({"Results": []})

    def test_empty_valid_results_pass(self):
        self.assertEqual(self.cmp(payload(), payload())["decision"], "PASS")

    def test_summary_markdown(self):
        report = self.cmp(payload(), payload(vuln()))
        s = mod.create_summary(report)
        self.assertIn("**FAIL**", s)
        self.assertIn("CVE-2026-DEMO", s)
        self.assertIn("HIGH", s)


if __name__ == "__main__":
    unittest.main()
