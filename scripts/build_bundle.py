#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic curated text bundles; no network, hardware or installation.

A successful bundle is a source snapshot, not a substitute for publication
privacy/license review. All captured bytes are hashed once and reused for both
archives. A final source comparison detects concurrent changes.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

EXCLUDED_DIRS = {'.git', '.cache', '.venv', 'venv', 'env', '__pycache__',
                 '.pytest_cache', '.mypy_cache', '.ruff_cache', 'dist', 'build',
                 'artifacts', 'publication_private', 'private', 'raw', 'captures',
                 'node_modules'}
EXCLUDED_NAMES = {'.DS_Store', 'AUTH_REQUIRED.md', 'harness', 'harness_sanitized', 'harness_regression_before_fix'}
TEXT_SUFFIXES = {'.py', '.json', '.md', '.toml', '.yaml', '.yml', '.cff',
                 '.patch', '.license', '.txt', '.c', '.h', '.svg', '.css', '.html', '.rst'}
TEXT_NAMES = {'LICENSE', 'NOTICE', 'Makefile', 'CODEOWNERS', '.gitignore',
              '.editorconfig', '.gitattributes', 'SHA256SUMS'}
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024


def _excluded_directory(name):
    return (name in EXCLUDED_DIRS or name.endswith(('.dSYM', '.egg-info', '.dist-info'))
            or name.lower().startswith('private_'))


def collect_files(root, out):
    """Return only ordinary, approved text paths without following symlinks."""
    root, out = Path(root).resolve(), Path(out).resolve()
    selected = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        here = Path(directory)
        dirs[:] = sorted(name for name in dirs
                         if not _excluded_directory(name)
                         and not (here / name).is_symlink()
                         and (here / name) != out)
        if here == out or out in here.parents:
            dirs[:] = []
            continue
        for name in files:
            path = here / name
            if (name in EXCLUDED_NAMES or name.lower().startswith('private_')
                    or path.is_symlink() or path.suffix.lower() not in TEXT_SUFFIXES
                    and name not in TEXT_NAMES):
                continue
            if stat.S_ISREG(path.lstat().st_mode):
                selected.append(path)
    return sorted(selected)


def _read_text(path):
    """Bounded ordinary UTF-8 bytes; final-path symlink races fail closed."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise ValueError('bundle input is not a bounded ordinary text file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES or b'\x00' in raw:
            raise ValueError('binary or oversized content rejected')
        raw.decode('utf-8')
        return raw, (0o755 if info.st_mode & 0o111 else 0o644)
    finally:
        os.close(fd)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _documentation(name):
    path = Path(name)
    return (path.suffix.lower() == '.md' or path.parts[0] in ('docs', 'evidence', 'LICENSES')
            or name in ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'CITATION.cff', 'RESEARCH_STATUS.json',
                        'patches/linux-functionfs/upstream.json'))


def _archive(path, snapshot):
    # Empty gzip filename and fixed tar/gzip timestamps make byte-identical
    # archives from equal inputs, regardless of temporary build location.
    with path.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name, raw, mode in snapshot:
                    relative = Path(name)
                    if relative.is_absolute() or '..' in relative.parts:
                        raise ValueError('unsafe archive path')
                    info = tarfile.TarInfo('openig831t/' + relative.as_posix())
                    info.size, info.mode, info.mtime = len(raw), mode, 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    archive.addfile(info, io.BytesIO(raw))
    path.chmod(0o600)


def build(root, out):
    root, out = Path(root).resolve(), Path(out).resolve()
    if not root.is_dir() or out == root:
        raise ValueError('distinct source and fresh output directories required')
    if any(out == Path(v) or Path(v) in out.parents for v in ('/dev', '/proc', '/sys')):
        raise ValueError('output must be an ordinary directory')
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    captured = []
    size = 0
    for path in collect_files(root, out):
        raw, mode = _read_text(path)
        size += len(raw)
        if size > MAX_SNAPSHOT_BYTES:
            raise ValueError('source snapshot exceeds bound')
        captured.append((path.relative_to(root).as_posix(), raw, mode))
    hashes = {name: _digest(raw) for name, raw, _ in captured}
    archive = out / 'openig831t_source.tar.gz'
    docs_archive = out / 'openig831t_documentation.tar.gz'
    _archive(archive, captured)
    docs = [row for row in captured if _documentation(row[0])]
    _archive(docs_archive, docs)
    after = {}
    changed_read_errors = []
    for path in collect_files(root, out):
        name = path.relative_to(root).as_posix()
        try:
            raw, _ = _read_text(path)
            after[name] = _digest(raw)
        except (OSError, ValueError, UnicodeError):
            changed_read_errors.append(name)
    changed = sorted(set(changed_read_errors) | {
        name for name in hashes.keys() | after.keys() if hashes.get(name) != after.get(name)})
    archives = {archive.name: _digest(archive.read_bytes()),
                docs_archive.name: _digest(docs_archive.read_bytes())}
    manifest = {'format_version': 1, 'archive': archive.name, 'sha256': archives[archive.name],
                'documentation_archive': docs_archive.name,
                'documentation_sha256': archives[docs_archive.name], 'files': hashes,
                'documentation_files': [name for name, _, _ in docs],
                'hardware_tested': False, 'privacy_review_required_separately': True,
                'status': 'PASS' if not changed else 'SOURCE_CHANGED_DURING_BUILD',
                'sources_changed_during_build': changed,
                'generated_host_harness_binaries_included': False,
                'license_note': 'Per-file licenses and third-party notices remain applicable.'}
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    (out / 'manifest.json').write_bytes(manifest_raw)
    checksums = dict(archives, **{'manifest.json': _digest(manifest_raw)})
    (out / 'SHA256SUMS').write_text(''.join(f'{sha}  {name}\n' for name, sha in sorted(checksums.items())))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New output directory; existing paths are refused')
    args = parser.parse_args()
    manifest = build(Path(__file__).resolve().parents[1], args.output)
    print(json.dumps({'archive': manifest['archive'], 'sha256': manifest['sha256'],
                      'files': len(manifest['files']), 'status': manifest['status']}, indent=2))
    return 0 if manifest['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
