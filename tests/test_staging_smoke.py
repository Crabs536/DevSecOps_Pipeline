import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'staging_smoke.py'
spec = importlib.util.spec_from_file_location('m7_staging', SOURCE)
m7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m7)

IMG = 'ghcr.io/crabs536/wrongsecrets-devsecops-lab:sha-' + 'a' * 40


def cp(rc=0, out='', err=''):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=out, stderr=err)


class FakeDocker:
    def __init__(self, scenario='success'):
        self.scenario = scenario
        self.calls = []
        self.removed = False

    def __call__(self, argv, *, timeout, input_text=None, env=None):
        self.calls.append((list(argv), timeout))
        if argv[:2] == ['docker', 'info']:
            return cp(out='29.0.0\n')
        if argv[:2] == ['docker', 'login']:
            if self.scenario == 'login_fail':
                return cp(rc=1, err='unauthorized: authentication required')
            assert input_text == 'test-token\n'
            assert 'DOCKER_CONFIG' in env
            return cp(out='Login Succeeded')
        if argv[:2] == ['docker', 'pull']:
            if self.scenario == 'pull_fail':
                return cp(rc=1, err='manifest unknown')
            if self.scenario == 'pull_timeout':
                raise subprocess.TimeoutExpired(argv, timeout)
            return cp(out='Pulled')
        if argv[:3] == ['docker', 'image', 'inspect']:
            return cp(out=json.dumps([{'Id': 'sha256:' + 'c'*64,
                                       'RepoDigests': ['ghcr.io/crabs536/wrongsecrets-devsecops-lab@sha256:' + 'd'*64]}]))
        if argv[:2] == ['docker', 'run']:
            if self.scenario == 'run_fail':
                return cp(rc=1, err='Cannot start container')
            return cp(out='container-id\n')
        if argv[:2] == ['docker', 'inspect']:
            state = {'Status': 'exited' if self.scenario == 'process_exit' else 'running',
                     'Running': self.scenario != 'process_exit', 'ExitCode': 1 if self.scenario == 'process_exit' else 0,
                     'OOMKilled': False}
            d = {'State': state, 'HostConfig': {'NetworkMode': 'bridge' if self.scenario == 'isolation_fail' else 'none',
                                               'PortBindings': None, 'Privileged': False}, 'Mounts': []}
            return cp(out=json.dumps([d]))
        if argv[:2] == ['docker', 'exec']:
            return cp(rc=127 if self.scenario == 'probe_missing' else 0)
        if argv[:3] == ['docker', 'logs', '--tail']:
            return cp(out='Bearer importantsecret\njava.lang.IllegalStateException: SECRET_API_KEY=secret\n')
        if argv[:3] == ['docker', 'rm', '-f']:
            self.removed = True
            return cp(rc=1 if self.scenario == 'cleanup_fail' else 0)
        raise AssertionError('Unknown command: ' + repr(argv))


class Milestone7Tests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(m7.shutil, 'which', return_value='/usr/bin/docker')
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_runner(self, td, fake, image=IMG):
        args = argparse.Namespace(image=image, report_dir=str(Path(td) / 'reports'),
                                  health_path='/', pull_timeout=100, health_timeout=10, interval=1)
        return m7.Smoke(args, command=fake)

    def load_report(self, td):
        return json.loads((Path(td) / 'reports' / 'report.json').read_text())

    def test_validate_image_accepts_only_private_lab_sha(self):
        self.assertEqual(m7.validate_image(IMG), IMG)
        for invalid in ['ghcr.io/evil/app:sha-' + 'a'*40,
                        'ghcr.io/crabs536/wrongsecrets-devsecops-lab:latest',
                        'ghcr.io/crabs536/wrongsecrets-devsecops-lab:sha-../evil']:
            with self.assertRaises(m7.StageFailure):
                m7.validate_image(invalid)

    def test_health_path_validation(self):
        self.assertEqual(m7.validate_health_path('/'), '/')
        self.assertEqual(m7.validate_health_path('/actuator/health'), '/actuator/health')
        for invalid in ['http://example.com', '/../../../', '/bad path', '/a;cat /etc/passwd']:
            with self.assertRaises(m7.StageFailure):
                m7.validate_health_path(invalid)

    def test_secrets_redacted(self):
        s = m7.redact('authorization=ABCDE token=HELLO Bearer 123secret ghp_' + 't'*30)
        self.assertNotIn('ABCDE', s)
        self.assertNotIn('HELLO', s)
        self.assertNotIn('123secret', s)
        self.assertNotIn('ghp_', s)

    def test_exception_names_no_raw_log(self):
        names = m7.exception_names('Caused by: java.lang.IllegalStateException: password=123\njava.lang.NullPointerException: secret')
        self.assertEqual(names, ['java.lang.IllegalStateException', 'java.lang.NullPointerException'])

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token', 'GHCR_USERNAME': 'Crabs536'})
    def test_success_isolated_cleanup_and_reports(self):
        with tempfile.TemporaryDirectory() as td:
            fake = FakeDocker()
            runner = self.make_runner(td, fake)
            self.assertEqual(runner.run(), 0)
            doc = self.load_report(td)
            self.assertEqual(doc['result'], 'PASS')
            self.assertTrue(doc['cleanup_ok'])
            self.assertTrue(fake.removed)
            cmds = [item[0] for item in fake.calls]
            run_cmd = next(c for c in cmds if c[:2] == ['docker', 'run'])
            self.assertIn('none', run_cmd)
            self.assertIn('--cap-drop', run_cmd)
            self.assertNotIn('-p', run_cmd)
            self.assertNotIn('--publish', run_cmd)
            self.assertEqual(doc['probe_attempts'], 1)
            self.assertNotIn('test-token', (Path(td) / 'reports' / 'summary.md').read_text())
            self.assertNotIn('test-token', (Path(td) / 'reports' / 'report.json').read_text())

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token'})
    def test_missing_ghcr_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            runner = self.make_runner(td, FakeDocker('login_fail'))
            self.assertEqual(runner.run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'GHCR_AUTH')
            self.assertTrue((Path(td) / 'reports' / 'summary.md').exists())

    def test_missing_token(self):
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ)
            env.pop('GHCR_TOKEN', None)
            env.pop('GITHUB_TOKEN', None)
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(self.make_runner(td, FakeDocker()).run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'GHCR_AUTH')

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token'})
    def test_image_pull_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_runner(td, FakeDocker('pull_fail'))
            self.assertEqual(r.run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'IMAGE_PULL')

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token'})
    def test_pull_timeout_reported(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_runner(td, FakeDocker('pull_timeout'))
            self.assertEqual(r.run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'IMAGE_PULL')

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token'})
    def test_app_exits_before_ready_and_no_raw_logs(self):
        with tempfile.TemporaryDirectory() as td:
            fake = FakeDocker('process_exit')
            self.assertEqual(self.make_runner(td, fake).run(), 1)
            doc = self.load_report(td)
            self.assertEqual(doc['error']['code'], 'CONTAINER_START')
            self.assertIn('java.lang.IllegalStateException', doc['exception_class_names'])
            self.assertNotIn('importantsecret', json.dumps(doc))
            self.assertTrue(fake.removed)

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token'})
    def test_missing_probe_tool(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(self.make_runner(td, FakeDocker('probe_missing')).run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'PROBE_TOOL_MISSING')

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token'})
    def test_fails_if_container_not_isolated(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(self.make_runner(td, FakeDocker('isolation_fail')).run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'ISOLATION')

    @mock.patch.dict(os.environ, {'GHCR_TOKEN': 'test-token'})
    def test_cleanup_failure_is_a_failure(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(self.make_runner(td, FakeDocker('cleanup_fail')).run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'CLEANUP')

    def test_invalid_image_gives_shareable_report(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(self.make_runner(td, FakeDocker(), image='wrong/unsafe:latest').run(), 1)
            self.assertEqual(self.load_report(td)['error']['code'], 'CONFIG')
            self.assertTrue((Path(td) / 'reports' / 'summary.md').exists())


if __name__ == '__main__':
    unittest.main()
