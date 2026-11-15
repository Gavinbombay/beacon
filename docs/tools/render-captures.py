#!/usr/bin/env python3
"""Render committed, actual terminal output as deterministic SVG screenshots.
Run from any directory with python3 -B docs/tools/render-captures.py.
The source captures are selected verbatim lines from sandboxed cargo test output.
"""
from pathlib import Path
from html import escape
import hashlib

root = Path(__file__).resolve().parents[1]
for source in sorted((root / "captures").glob("*.txt")):
    lines = source.read_text().splitlines()
    width = max(800, max((len(line) for line in lines), default=0) * 9 + 64)
    height = 104 + len(lines) * 26
    elements = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Terminal capture of actual test output">',
                f'<rect width="{width}" height="{height}" rx="18" fill="#101c2b"/>',
                '<circle cx="26" cy="27" r="5" fill="#ffb86b"/>',
                '<circle cx="46" cy="27" r="5" fill="#5bd5cf"/>',
                '<text x="68" y="33" fill="#d7e3f0" font-family="monospace" font-size="15">Beacon / terminal capture</text>']
    for index, line in enumerate(lines):
        elements.append(f'<text x="26" y="{80 + index * 26}" fill="#d7e3f0" font-family="monospace" font-size="14">{escape(line)}</text>')
    elements.append('</svg>')
    output = source.with_suffix('.svg')
    output.write_text('\n'.join(elements) + '\n')
    print(output.relative_to(root), hashlib.sha256(output.read_bytes()).hexdigest())
