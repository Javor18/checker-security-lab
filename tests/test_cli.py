"""Offline CLI checks. Network/deployment commands are replaced with tripwires."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = next((ROOT / 'scripts').glob('*.sh'))
BASH = os.environ.get('PORTFOLIO_BASH') or shutil.which('bash')

class CliTests(unittest.TestCase):
    def run_script(self, *args):
        self.assertTrue(BASH, 'Bash is required')
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            record = folder / 'side-effects.txt'
            commands = ['nmap', 'hydra', 'ssh', 'sshpass', 'apt-get', 'sudo', 'apachectl',
                        'a2ensite', 'systemctl', 'curl', 'wget', 'php', 'certbot',
                        'bulk_extractor', 'foremost', 'binwalk', 'vol', 'arpspoof']
            for name in commands:
                stub = folder / name
                stub.write_text('#!/usr/bin/env bash\nprintf "called\\n" >> "$PORTFOLIO_TRIPWIRE"\nexit 97\n', encoding='utf-8')
                stub.chmod(0o755)
            env = dict(os.environ)
            env['PORTFOLIO_TRIPWIRE'] = record.as_posix()
            # Set PATH inside Bash so the tripwires also work with Git Bash on Windows.
            command = 'export PATH="$1:$PATH"; shift; exec "$@"'
            result = subprocess.run([BASH, '-c', command, 'cli-test', folder.as_posix(),
                                     BASH, SCRIPT.as_posix(), *args],
                                    cwd=folder, env=env, capture_output=True, text=True, timeout=15)
            self.assertFalse(record.exists(), 'CLI-only invocation attempted a side effect')
            return result

    def test_bash_syntax(self):
        result = subprocess.run([BASH, '-n', str(SCRIPT)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_long_help_is_safe(self):
        result = self.run_script('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Usage:', result.stdout)

    def test_short_help_is_safe(self):
        result = self.run_script('-h')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Usage:', result.stdout)

    def test_unknown_option_is_rejected_before_side_effects(self):
        result = self.run_script('--portfolio-unknown-option')
        self.assertNotEqual(result.returncode, 0)

if __name__ == '__main__':
    unittest.main()
