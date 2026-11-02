from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = next((ROOT / 'scripts').glob('*.sh'))
BASH = os.environ.get('PORTFOLIO_BASH') or shutil.which('bash')

class FunctionTests(unittest.TestCase):
    def evaluate(self, expression):
        env = dict(os.environ)
        import sys
        env['PORTFOLIO_PYTHON'] = Path(sys.executable).as_posix()
        command = 'source "$1"; shift; python3() { "$PORTFOLIO_PYTHON" "$@"; }; ' + expression
        return subprocess.run([BASH, '-c', command, 'function-test', SCRIPT.as_posix()],
                              capture_output=True, text=True, env=env, timeout=15)

    def test_ipv4_boundaries(self):
        for value in ['0.0.0.0', '192.168.56.10', '255.255.255.255']:
            self.assertEqual(self.evaluate(f'valid_ipv4 "{value}"').returncode, 0, value)
        for value in ['256.0.0.1', '1.2.3', '1.2.3.4;id']:
            self.assertNotEqual(self.evaluate(f'valid_ipv4 "{value}"').returncode, 0, value)

    def test_port_list_boundaries(self):
        for value in ['1', '65535', '22,80,443', '8000-8100']:
            self.assertEqual(self.evaluate(f'valid_port_list "{value}"').returncode, 0, value)
        for value in ['0', '65536', '80-22', '22,,80', '22;id']:
            self.assertNotEqual(self.evaluate(f'valid_port_list "{value}"').returncode, 0, value)
