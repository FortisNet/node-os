#!/usr/bin/env python3
"""The gate: `make verify`.

It builds a small toolchain image (tools/Dockerfile.verify), mounts this
repository into it with the network switched off, and runs:

  clang      build with Clang and libc++, then every test
  gcc        build with GCC, then every test
  sanitizers build with AddressSanitizer and UndefinedBehaviorSanitizer, run
             every test under them, then fuzz the parsers for a minute
  analyzer   the Clang Static Analyzer on every source file
  lint       clang-tidy on every source file, clang-format on all but lib/
  cppcheck   cppcheck on every source file
  python     pyflakes on every Python file

The result is build-verify/report.json: one return code per stage, the hash
of every input file, and whether any of them changed while the gate ran. A
release of the orchestrator is built only from a tree whose report is
complete, passing and still matches (see `--check-inputs`).

  verify.py                 run every stage
  verify.py --stage NAME    run one stage; the report is then not complete
  verify.py --check-inputs  exit 0 only if the report passes and matches
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / 'build-verify'
REPORT = OUTPUT / 'report.json'
STAGES = ('clang', 'gcc', 'sanitizers', 'analyzer', 'lint', 'cppcheck', 'python')
SKIPPED = {'.git', 'build', 'build-verify', 'build-release', 'dist', '__pycache__', '.DS_Store'}
COMPILERS = {'clang': ('clang-18', 'clang++-18', ' -stdlib=libc++'), 'gcc': ('gcc-13', 'g++-13', ''),
             # With the GNU standard library: the fuzzing runtime Ubuntu ships is built for it.
             'sanitizers': ('clang-18', 'clang++-18', ' -g -fno-omit-frame-pointer'
                            ' -fsanitize=address,undefined,fuzzer-no-link -fno-sanitize-recover=all')}
# A finding stops the program that has it, so the test that ran it fails.
SANITIZER_OPTIONS = {'ASAN_OPTIONS': 'abort_on_error=1:detect_leaks=1',
                     'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
# The copies in lib/ keep the formatting of the node they came from; everything
# else follows .clang-format.
FORMATTED = ('orchestrator', 'sandbox', 'tests')


def input_hashes():
    """Every file that can change what this gate builds or checks."""
    hashes = {}
    for path in sorted(HERE.rglob('*')):
        relative = path.relative_to(HERE)
        if not path.is_file() or SKIPPED & set(relative.parts):
            continue
        if relative.parts[0] == '.deps' and path.suffix != '.bz2':
            continue
        hashes[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def passing(report, hashes):
    stages = report.get('stages', {})
    return bool(report.get('complete') and report.get('inputs_unchanged') and set(stages) == set(STAGES)
                and not any(stage['returncode'] for stage in stages.values())
                and report.get('input_sha256') == hashes)


def run(command, log, **options):
    print('$ ' + ' '.join(shlex.quote(str(word)) for word in command), flush=True)
    with log.open('a') as output:
        output.write('$ ' + ' '.join(map(str, command)) + '\n')
        output.flush()
        code = subprocess.run([str(word) for word in command], cwd=HERE, stdout=output,
                              stderr=subprocess.STDOUT, **options).returncode
    if code:
        print(''.join(log.read_text(errors='replace').splitlines(keepends=True)[-40:]), flush=True)
    return code


def make(compiler, *targets):
    cc, cxx, extra = COMPILERS[compiler]
    flags = subprocess.check_output(['make', '-s', 'print-default-flags'], cwd=HERE, text=True).strip()
    return ['make', f'-j{os.cpu_count() or 2}', f'BUILD=build-verify/{compiler}', f'CC={cc}', f'CXX={cxx}',
            f'CXXFLAGS={flags}{extra}', *targets]


def sources():
    return subprocess.check_output(['make', '-s', 'print-sources'], cwd=HERE, text=True).split()


def compile_flags():
    """Flags of the Clang build, whose Mbed TLS headers the checkers read."""
    line = subprocess.check_output(make('clang', '-s', 'print-flags'), cwd=HERE, text=True)
    return [flag for flag in shlex.split(line) if flag != '-Werror']


def each(names, one, log):
    """Run `one(name)` -> (return code, output) for every name, in parallel."""
    failed = 0
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 2) as pool, log.open('a') as output:
        for name, (code, text) in zip(names, pool.map(one, names)):
            output.write(f'== {name}: {code}\n{text}\n')
            if code:
                failed += 1
                print(f'{name}\n{text[-3000:]}', flush=True)
    return failed


def stage(name, log):
    if name == 'sanitizers':
        return run(make(name, 'test', 'fuzz'), log, env={**os.environ, **SANITIZER_OPTIONS})
    if name in COMPILERS:
        return run(make(name, 'test'), log)
    if name == 'python':
        files = sorted(str(path.relative_to(HERE)) for path in HERE.rglob('*.py')
                       if not SKIPPED & set(path.relative_to(HERE).parts))
        return run(['pyflakes3', *files], log)
    # The checkers read the Mbed TLS headers and the generated page shell of
    # the Clang build tree.
    if run(make('clang', 'build-verify/clang/mbedtls-3.6.7/.built', 'build-verify/clang/generated/page_shell.inc'), log):
        return 1
    flags, files = compile_flags(), sources()
    if name == 'analyzer':
        def analyze(source):
            result = subprocess.run(['clang++-18', '--analyze', '-Xanalyzer', '-analyzer-output=text', *flags,
                                     source, '-o', '/dev/null'], cwd=HERE, capture_output=True, text=True,
                                    errors='replace')
            text = result.stdout + result.stderr
            return (result.returncode or int('warning:' in text)), text
        return int(bool(each(files, analyze, log)))
    if name == 'lint':
        def tidy(source):
            result = subprocess.run(['clang-tidy-18', '--quiet', '--warnings-as-errors=*', source, '--', *flags],
                                    cwd=HERE, capture_output=True, text=True, errors='replace')
            text = result.stdout + result.stderr
            return (result.returncode or int(' warning: ' in text or ' error: ' in text)), text
        failed = each(files, tidy, log)
        own = sorted(str(path.relative_to(HERE)) for directory in FORMATTED
                     for path in (HERE / directory).glob('*') if path.suffix in ('.cpp', '.h'))
        failed += run(['clang-format-18', '--style=file', '--dry-run', '--Werror', *own], log)
        return int(bool(failed))
    includes = [flag for flag in flags if flag.startswith(('-I', '-D'))]
    cache = OUTPUT / 'cppcheck-cache'
    cache.mkdir(exist_ok=True)
    return run(['cppcheck', '--enable=warning,performance,portability', '--inline-suppr', '--error-exitcode=1',
                '--std=c++23', '--platform=unix64', '--language=c++', '-D__EXCEPTIONS=1',
                '-D__cpp_exceptions=199711L', '--suppress=*:*/mbedtls-3.6.7/*',
                '--suppress=assertWithSideEffect:tests/*', '--suppress=missingIncludeSystem',
                f'--cppcheck-build-dir={cache}', '--template=gcc', f'-j{os.cpu_count() or 2}',
                *includes, *files], log)


def inside(selected):
    OUTPUT.mkdir(exist_ok=True)
    logs = OUTPUT / 'logs'
    logs.mkdir(exist_ok=True)
    before = input_hashes()
    report = {'started_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
              'complete': False, 'stages': {}, 'input_sha256': before,
              'tool_versions': {tool: subprocess.run([tool, '--version'], capture_output=True, text=True)
                                .stdout.splitlines()[0]
                                for tool in ('clang-18', 'gcc-13', 'clang-tidy-18', 'cppcheck', 'pyflakes3')}}
    for name in selected:
        log = logs / f'{name}.log'
        log.unlink(missing_ok=True)
        started = time.monotonic()
        code = stage(name, log)
        report['stages'][name] = {'returncode': code, 'seconds': round(time.monotonic() - started, 2)}
        print(f'verify: {name}: {"PASS" if code == 0 else "FAIL"}', flush=True)
    report['inputs_unchanged'] = input_hashes() == before
    report['complete'] = tuple(selected) == STAGES
    REPORT.write_text(json.dumps(report, indent=2) + '\n')
    if not report['inputs_unchanged']:
        print('verify: an input file changed while the gate ran; the report does not count', flush=True)
    return 0 if report['inputs_unchanged'] and not any(s['returncode'] for s in report['stages'].values()) else 1


def outside(arguments):
    recipe = HERE / 'tools/Dockerfile.verify'
    tag = 'fortis-node-os-verify:' + hashlib.sha256(recipe.read_bytes()).hexdigest()[:12]
    if subprocess.run(['docker', 'image', 'inspect', tag], capture_output=True).returncode:
        with recipe.open('rb') as source:
            subprocess.run(['docker', 'build', '-t', tag, '-'], stdin=source, check=True)
    # The archive is fetched here: the gate's container needs no network.
    subprocess.run([str(HERE / 'tools/fetch-mbedtls.sh')], check=True)
    command = ['docker', 'run', '--rm', '--init', '--network', 'none', '-v', f'{HERE}:/work', '-w', '/work',
               '-e', 'FORTIS_VERIFY_CONTAINER=1', '-e', 'PYTHONDONTWRITEBYTECODE=1']
    if sys.platform.startswith('linux'):
        command += ['--user', f'{os.getuid()}:{os.getgid()}', '-e', 'HOME=/tmp']
    return subprocess.run(command + [tag, 'python3', 'verify.py', *arguments]).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--stage', choices=STAGES)
    parser.add_argument('--check-inputs', action='store_true')
    options = parser.parse_args()
    if options.check_inputs:
        if not REPORT.is_file() or not passing(json.loads(REPORT.read_text()), input_hashes()):
            print('There is no complete, passing verification report for these files: '
                  'run make verify', file=sys.stderr)
            return 1
        print('The verification report is complete, passing and matches these files')
        return 0
    if os.environ.get('FORTIS_VERIFY_CONTAINER') != '1':
        return outside(sys.argv[1:])
    return inside((options.stage,) if options.stage else STAGES)


if __name__ == '__main__':
    sys.exit(main())
