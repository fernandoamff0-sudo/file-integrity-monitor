"""Offline SHA-256 file integrity snapshots and comparisons."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


class MonitorError(ValueError):
    """An input or filesystem operation prevents a complete comparison."""


def directory(path):
    path = Path(path)
    if path.is_symlink():
        raise MonitorError('The root directory must not be a symbolic link.')
    root = path.resolve()
    if not root.is_dir():
        raise MonitorError(f'Not a directory: {path}')
    return root


def baseline_path(path, root):
    path = Path(path).absolute()
    if path.is_symlink():
        raise MonitorError('The baseline must not be a symbolic link.')
    resolved = path.resolve()
    if resolved == root or root in resolved.parents:
        raise MonitorError('Store the baseline outside the monitored directory.')
    return path


def hash_file(path):
    """Hash in chunks and reject files observed changing during the read."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise MonitorError(f'Not a regular file: {path}')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, field) != getattr(after, field) for field in fields) or (
        current.st_dev, current.st_ino
    ) != (after.st_dev, after.st_ino):
        raise MonitorError(f'File changed during scan; retry with writers stopped: {path}')
    return {'sha256': digest.hexdigest(), 'size': after.st_size}


def scan(root):
    """Inventory regular files. Never silently skip unreadable paths or symlinks."""
    root = directory(root)
    files = {}

    def visit(folder):
        with os.scandir(folder) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                if entry.name == '.git':
                    continue
                path = Path(entry.path)
                if entry.is_symlink():
                    raise MonitorError(f'Symbolic links are unsupported: {path}')
                if entry.is_dir(follow_symlinks=False):
                    visit(path)
                elif entry.is_file(follow_symlinks=False):
                    files[path.relative_to(root).as_posix()] = hash_file(path)
                else:
                    raise MonitorError(f'Special files are unsupported: {path}')
    try:
        visit(root)
    except (OSError, RecursionError) as exc:
        raise MonitorError(f'Cannot complete scan: {exc}') from exc
    return dict(sorted(files.items()))


def make_baseline(root):
    return {'version': 1, 'algorithm': 'sha256', 'excluded_names': ['.git'],
            'created_at': datetime.now(timezone.utc).isoformat(), 'files': scan(root)}


def validate_baseline(data):
    if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1:
        raise MonitorError('Unsupported baseline version; expected version 1.')
    if data.get('algorithm') != 'sha256' or data.get('excluded_names') != ['.git']:
        raise MonitorError('Unsupported baseline algorithm or exclusion policy.')
    files = data.get('files')
    if not isinstance(files, dict):
        raise MonitorError('Baseline files must be an object.')
    for name, item in files.items():
        parts = name.split('/')
        if not name or PurePosixPath(name).is_absolute() or any(p in ('', '.', '..') for p in parts) or '\\' in name or '.git' in parts:
            raise MonitorError(f'Invalid baseline relative path: {name!r}')
        if not isinstance(item, dict) or not isinstance(item.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
            raise MonitorError(f'Invalid SHA-256 entry: {name!r}')
        if type(item.get('size')) is not int or item['size'] < 0:
            raise MonitorError(f'Invalid size entry: {name!r}')
    return data


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise MonitorError(f'Duplicate key in baseline: {name!r}')
        result[name] = value
    return result


def load_baseline(path):
    try:
        with Path(path).open(encoding='utf-8') as stream:
            return validate_baseline(json.load(stream, object_pairs_hook=_unique_object))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise MonitorError(f'Cannot load baseline: {exc}') from exc


def write_baseline(path, data):
    """Create exclusively: never replace an existing baseline."""
    payload = json.dumps(data, indent=2, ensure_ascii=True) + '\n'
    created = False
    try:
        with Path(path).open('x', encoding='utf-8') as stream:
            created = True
            stream.write(payload)
    except OSError as exc:
        if created:
            Path(path).unlink(missing_ok=True)
        raise MonitorError(f'Cannot create baseline (existing files are never overwritten): {exc}') from exc


def compare(baseline, current):
    previous = validate_baseline(baseline)['files']
    added = sorted(current.keys() - previous.keys())
    deleted = sorted(previous.keys() - current.keys())
    modified = sorted(name for name in previous.keys() & current.keys() if previous[name] != current[name])
    return {'status': 'changed' if added or deleted or modified else 'unchanged',
            'scanned_files': len(current), 'added': added, 'modified': modified, 'deleted': deleted,
            'notice': 'Changes require review; they do not prove malicious activity. The baseline must be trusted.'}


def format_report(report):
    lines = ['FILE INTEGRITY MONITOR', '======================']
    if report['status'] == 'baseline_created':
        lines += [f"Baseline created: {report['baseline']}", f"Files recorded: {report['scanned_files']}"]
    else:
        lines += [f"Status: {report['status']}", f"Files scanned: {report['scanned_files']}", report['notice']]
        for category in ('added', 'modified', 'deleted'):
            lines.append(f'{category.capitalize()}: {len(report[category])}')
            lines.extend('  ' + json.dumps(name, ensure_ascii=True) for name in report[category])
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='command', required=True)
    for command in ('baseline', 'check'):
        sub = subparsers.add_parser(command)
        sub.add_argument('directory', type=Path, help='Folder to monitor')
        sub.add_argument('baseline', type=Path, help='Baseline JSON, outside the monitored folder')
        sub.add_argument('--format', choices=('text', 'json'), default='text')
    args = parser.parse_args(argv)
    try:
        root = directory(args.directory)
        path = baseline_path(args.baseline, root)
        if args.command == 'baseline':
            if path.exists():
                raise MonitorError('Baseline already exists. Choose a new path; review changes before rebaselining.')
            data = make_baseline(root)
            write_baseline(path, data)
            report = {'status': 'baseline_created', 'baseline': str(path), 'scanned_files': len(data['files'])}
        else:
            data = load_baseline(path)
            report = compare(data, scan(root))
    except (MonitorError, OSError, RuntimeError, RecursionError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=True) if args.format == 'json' else format_report(report))
    return 1 if report['status'] == 'changed' else 0


if __name__ == '__main__':
    sys.exit(main())
