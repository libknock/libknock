#!/usr/bin/env python3
from pathlib import Path
import re, sys
root = Path(__file__).resolve().parents[1]
missing = []
for md in root.glob('**/*.md'):
    if any(part in {'.git', 'vendor'} for part in md.parts):
        continue
    text = md.read_text(encoding='utf-8')
    for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
        if '://' in target or target.startswith('#') or target.startswith('mailto:'):
            continue
        path = target.split('#', 1)[0]
        if not path:
            continue
        if not (md.parent / path).exists():
            missing.append(f'{md.relative_to(root)} -> {target}')
if missing:
    print('\n'.join(missing))
    sys.exit(1)
