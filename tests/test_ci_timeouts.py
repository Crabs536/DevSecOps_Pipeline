import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).resolve().parents[1] / 'extend_ci_timeouts.py'
spec = importlib.util.spec_from_file_location('m7_timeout', p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TimeoutPatchTests(unittest.TestCase):
    def test_update_only_target_job(self):
        y = '''jobs:
  pr-security-gate:
    name: pr-security-gate
    timeout-minutes: 60
    steps:
      - name: example
        timeout-minutes: 4
  pr-report-comment:
    timeout-minutes: 10
'''
        v = mod.patch_job_timeout(y, 'pr-security-gate', 120)
        self.assertIn('    timeout-minutes: 120', v)
        self.assertIn('        timeout-minutes: 4', v)
        self.assertIn('  pr-report-comment:\n    timeout-minutes: 10', v)

    def test_no_shortening(self):
        y = 'jobs:\n  container-security-gate:\n    timeout-minutes: 150\n'
        self.assertEqual(mod.patch_job_timeout(y, 'container-security-gate', 120), y)

    def test_missing_fails_safe(self):
        with self.assertRaises(ValueError):
            mod.patch_job_timeout('jobs:\n  other:\n    timeout-minutes: 30', 'pr-security-gate', 120)


if __name__ == '__main__':
    unittest.main()
