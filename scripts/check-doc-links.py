#!/usr/bin/env python3
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]


def markdown_files():
    try:
        out = subprocess.check_output(
            ['git', 'ls-files', '*.md'], cwd=root, text=True, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError):
        out = ''
    files = [root / line for line in out.splitlines() if line]
    if files:
        return files
    return [
        p for p in root.glob('**/*.md')
        if not any(part in {'.git', 'vendor'} for part in p.parts)
    ]

missing = []
for md in markdown_files():
    if any(part in {'.git', 'vendor'} for part in md.parts):
        continue
    text = md.read_text(encoding='utf-8')
    for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
        if '://' in target or target.startswith('#') or target.startswith('mailto:'):
            continue
        path = target.split('#', 1)[0]
        if not path:
            continue
        if path.startswith('/'):
            continue
        if not (md.parent / path).exists():
            missing.append(f'{md.relative_to(root)} -> {target}')
if missing:
    print('\n'.join(missing))
    sys.exit(1)
