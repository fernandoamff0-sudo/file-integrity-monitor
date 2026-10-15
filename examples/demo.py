"""Run a repeatable demonstration in a temporary directory; no user files change."""
from pathlib import Path
import subprocess
import sys
import tempfile

MONITOR = Path(__file__).resolve().parent.parent / 'monitor.py'


def run(*args, expected=0):
    result = subprocess.run([sys.executable, str(MONITOR), *map(str, args)], capture_output=True, text=True)
    if result.returncode != expected:
        raise RuntimeError(result.stderr or result.stdout)
    print(result.stdout, end='')


def main():
    with tempfile.TemporaryDirectory(prefix='integrity-demo-') as temp:
        root = Path(temp) / 'files'
        root.mkdir()
        (root / 'config.txt').write_text('mode=demo\n', encoding='utf-8')
        (root / 'obsolete.txt').write_text('old\n', encoding='utf-8')
        baseline = Path(temp) / 'baseline.json'
        run('baseline', root, baseline)
        run('check', root, baseline)
        (root / 'config.txt').write_text('mode=updated\n', encoding='utf-8')
        (root / 'obsolete.txt').unlink()
        (root / 'new.txt').write_text('new\n', encoding='utf-8')
        run('check', root, baseline, '--format', 'json', expected=1)


if __name__ == '__main__':
    main()
