#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Parse project Python without imports, hardware access or bytecode writes."""
import ast
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    files = [p for folder in ('src', 'tests', 'scripts', 'tools')
             for p in (ROOT/folder).rglob('*.py') if '__pycache__' not in p.parts]
    for path in files:
        ast.parse(path.read_text(), filename=str(path.relative_to(ROOT)))
    ruff = shutil.which('ruff')
    if ruff:
        subprocess.run([ruff, 'check', 'src', 'tests', 'scripts', 'tools'], cwd=ROOT, check=True)
    print(f'PASS: parsed {len(files)} Python files; ruff={"PASS" if ruff else "not installed"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
