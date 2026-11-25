#!/usr/bin/env python3
"""Plan the removal of packages from an Alpine root filesystem, offline.

The image is edited with debugfs, without mounting it or running anything
from it, so the package manager cannot be asked to remove a package. This
script reads the package database instead and writes:

  remove.debugfs   debugfs commands deleting every file the packages own
  installed.new    the database without those packages
  world.new        the list of wanted packages without them
  packages.tsv     name, installed bytes and description of what remains

It refuses when a package that stays depends on one that goes, and when a
package that remains has no stated reason in packages.why. The second rule
keeps the README honest: nothing is in the image unexplained.

usage: trim_packages.py INSTALLED WORLD REMOVE_LIST PACKAGES_WHY OUTPUT_DIR
"""
from pathlib import Path
import sys


def parse(text):
    packages = []
    for block in text.strip().split('\n\n'):
        fields, files, directory = {}, [], ''
        for line in block.split('\n'):
            key, _, value = line.partition(':')
            if key == 'F':
                directory = value
            elif key == 'R':
                files.append('/' + (directory + '/' if directory else '') + value)
            elif key in ('P', 'I', 'T', 'D', 'p'):
                fields[key] = value
        packages.append({'name': fields['P'], 'bytes': int(fields.get('I', 0)), 'about': fields.get('T', ''),
                         'needs': fields.get('D', '').split(), 'provides': fields.get('p', '').split(),
                         'files': files, 'block': block})
    return packages


def bare(token):
    """A dependency or provided name without its version constraint."""
    for mark in ('>=', '<=', '=', '>', '<', '~'):
        token = token.split(mark)[0]
    return token


def main():
    installed, world, remove_list, reasons, output = map(Path, sys.argv[1:6])
    packages = parse(installed.read_text())
    listed = {line.split('#')[0].strip() for line in remove_list.read_text().splitlines()} - {''}
    # A line starting with "+" names a package to keep on the wanted list in
    # its own right, when the group package that pulled it in is removed.
    add = {name[1:] for name in listed if name.startswith('+')}
    remove = {name for name in listed if not name.startswith('+')}
    names = {package['name'] for package in packages}
    unknown = remove - names
    if unknown:
        sys.exit(f'not installed, so cannot be removed: {sorted(unknown)}')
    kept = [package for package in packages if package['name'] not in remove]
    still_provided = {package['name'] for package in kept} | \
                     {bare(token) for package in kept for token in package['provides']}
    for package in kept:
        for need in package['needs']:
            if need.startswith('!'):
                continue
            if bare(need) not in still_provided:
                sys.exit(f'{package["name"]} stays and needs {need}, which only a removed package provides')
    why = {}
    for line in reasons.read_text().splitlines():
        if line.strip() and not line.startswith('#'):
            name, _, reason = line.partition('\t')
            why[name.strip()] = reason.strip()
    unexplained = sorted(package['name'] for package in kept if not why.get(package['name']))
    if unexplained:
        sys.exit(f'packages.why gives no reason for: {unexplained}')
    stale = sorted(set(why) - {package['name'] for package in kept})
    if stale:
        sys.exit(f'packages.why explains packages that are not in the image: {stale}')
    kept_files = {path for package in kept for path in package['files']}
    commands = []
    for package in packages:
        if package['name'] in remove:
            commands += [f'rm {path}' for path in package['files'] if path not in kept_files]
    wanted = sorted({line for line in world.read_text().split() if bare(line) not in remove} | add)
    if add - {package['name'] for package in kept}:
        sys.exit(f'cannot keep packages that are not installed: {sorted(add)}')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'remove.debugfs').write_text('\n'.join(commands) + '\n')
    (output / 'installed.new').write_text('\n\n'.join(package['block'] for package in kept) + '\n\n')
    (output / 'world.new').write_text('\n'.join(wanted) + '\n')
    (output / 'packages.tsv').write_text(''.join(
        f'{package["name"]}\t{package["bytes"]}\t{package["about"]}\n'
        for package in sorted(kept, key=lambda item: -item['bytes'])))
    freed = sum(package['bytes'] for package in packages if package['name'] in remove)
    print(f'removing {len(remove)} packages, {len(commands)} files, {freed // 1024} KiB; {len(kept)} remain')


if __name__ == '__main__':
    main()
