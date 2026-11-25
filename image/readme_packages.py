#!/usr/bin/env python3
"""Write or check the package table in image/README.md.

  readme_packages.py write PACKAGES_TSV   after an image build: sizes from the image
  readme_packages.py check                in the gate: names and reasons match packages.why

The table sits between two marker lines. Reasons come from packages.why and
the removed list from packages.remove, so the README cannot describe an image
other than the one the build produces.
"""
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
README = HERE / 'README.md'
BEGIN, END = '<!-- packages:begin -->', '<!-- packages:end -->'


def reasons():
    groups, current = [], None
    for line in (HERE / 'packages.why').read_text().splitlines():
        if line.startswith('# ') and '\t' not in line and not line.endswith('.') and len(line) < 40:
            current = (line[2:], [])
            groups.append(current)
        elif '\t' in line and current is not None:
            name, _, reason = line.partition('\t')
            current[1].append((name.strip(), reason.strip()))
    return groups


def removed():
    rows = []
    for line in (HERE / 'packages.remove').read_text().splitlines():
        name, _, reason = line.partition('#')
        if name.strip() and not name.startswith('+') and not line.startswith('#'):
            rows.append((name.strip(), reason.strip()))
    return rows


def shown(size):
    if size is None:
        return ''
    if size == 0:
        return 'none'
    return f'{size / 1048576:.2f} MB' if size >= 104858 else f'{max(size // 1024, 1)} KB'


def parsed(text):
    text = text.strip()
    if text.endswith('MB'):
        return round(float(text[:-3]) * 1048576)
    if text.endswith('KB'):
        return int(text[:-3]) * 1024
    return 0 if text == 'none' else None


def table(sizes):
    # Totals are taken from the values as shown, so a check that reads the
    # table back computes the same numbers.
    sizes = {name: parsed(shown(size)) for name, size in sizes.items()}
    lines = [BEGIN, '']
    total = 0
    for title, rows in reasons():
        lines += [f'**{title}**', '', '| Package | Size | Why it is in the image |', '| --- | ---: | --- |']
        for name, reason in rows:
            total += sizes.get(name) or 0
            lines.append(f'| `{name}` | {shown(sizes.get(name))} | {reason} |')
        lines.append('')
    count = sum(len(rows) for _, rows in reasons())
    lines += [f'{count} packages, {total / 1048576:.1f} MB installed.', '', '**Removed from the Alpine base**', '',
              '| Package | Why it was removed |', '| --- | --- |']
    lines += [f'| `{name}` | {reason} |' for name, reason in removed()]
    return '\n'.join(lines + ['', END])


def current_sizes(text):
    return {name: parsed(size) for name, size in re.findall(r'^\| `([^`]+)` \| ([^|]*) \|', text, re.M)
            if parsed(size) is not None}


def main():
    text = README.read_text()
    start, end = text.index(BEGIN), text.index(END) + len(END)
    if sys.argv[1] == 'write':
        sizes = {name: int(size) for name, size, _ in
                 (line.split('\t') for line in Path(sys.argv[2]).read_text().splitlines())}
        README.write_text(text[:start] + table(sizes) + text[end:])
        return 0
    expected = table(current_sizes(text[start:end]))
    if text[start:end] != expected:
        print('FAIL: image/README.md does not match packages.why and packages.remove; '
              'run readme_packages.py write with the image build\'s packages.tsv')
        return 1
    print('image README matches packages.why and packages.remove')
    return 0


if __name__ == '__main__':
    sys.exit(main())
