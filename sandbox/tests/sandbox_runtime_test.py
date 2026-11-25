#!/usr/bin/env python3
"""Privileged disposable Linux integration. NEVER run directly on a real host.

Requires a Docker private cgroup namespace; the outer runner sets the marker.
No persistent volumes, host PID/network namespaces or Docker socket are mounted.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def main():
    assert os.environ.get('FORTIS_DISPOSABLE_SANDBOX_TEST') == '1'
    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    assert Path('/proc/self/cgroup').read_text().strip() == '0::/'
    # Enable controllers only in this container's private, delegated subtree.
    cg = Path('/sys/fs/cgroup')
    (cg / 'test-control').mkdir()
    for pid in (cg / 'cgroup.procs').read_text().split():
        try:
            (cg / 'test-control/cgroup.procs').write_text(pid)
        except ProcessLookupError:
            pass
    (cg / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    root = Path('/opt/fortis-sandboxes/images/fixture/rootfs')
    for directory in ('', 'bin', 'proc', 'tmp', 'dev'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    shutil.copyfile('/bin/busybox', root / 'bin/busybox')
    shutil.copyfile('/sandbox-payload', root / 'bin/probe')
    for name in ('busybox', 'probe'):
        (root / 'bin' / name).chmod(0o555)
    (root / 'bin/sh').symlink_to('busybox')
    Path('/host-secret').write_text('must not cross sandbox root')
    binary = str(Path(sys.argv[1]).resolve())
    backend = sys.argv[2]
    runtime = '/usr/local/bin/runsc' if backend == 'gvisor' else '/usr/bin/crun'
    settings = {'schemaVersion': 1, 'isolation': backend, 'runtime': runtime,
                'runtimeSha256': hashlib.sha256(Path(runtime).read_bytes()).hexdigest(),
                'maxJobs': 2, 'cpuBudgetMillicores': 2000, 'memoryBudgetMiB': 1024}
    for registry in ('/etc/subuid', '/etc/subgid'):
        Path(registry).write_text('fortis-sandbox:1048576:131072\n')
    policy = Path('/root/sandbox-policy.json')
    policy.write_text(json.dumps(settings)); policy.chmod(0o600)
    jobs = Path('/var/lib/fortis-sandboxes/jobs')
    checks = []
    observed_executables = set()

    def call(*args, code=0):
        result = subprocess.run([binary, str(policy), *map(str, args)], capture_output=True,
                                text=True, timeout=40)
        assert result.returncode == code, (args, result, list(jobs.glob('*/output.log')))
        return result

    def record(job):
        return json.loads((jobs / job / 'record').read_text().splitlines()[0])

    def output(job):
        return (jobs / job / 'output.log').read_text(errors='replace')

    def wait_for(job, state='running'):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            try:
                current = record(job)
                if current['state'] == state:
                    return current
                assert current['state'] == 'starting', (job, current, output(job))
            except FileNotFoundError:
                pass
            time.sleep(.02)
        raise AssertionError(('not ready', job))

    def close_streams():
        os.close(0)
        os.close(1)

    def launch(job, mode, close_stdio=False, **limits):
        spec = Path('/root') / (job + '.json')
        spec.write_text(json.dumps({'schemaVersion': 1, 'id': job, 'image': 'fixture',
                                   'args': ['/bin/probe', mode], 'timeoutSeconds': 10} | limits))
        return subprocess.Popen([binary, str(policy), 'run', str(spec)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                preexec_fn=close_streams if close_stdio else None)

    def finish(process, job, state, code):
        stdout, stderr = process.communicate(timeout=40)
        actual = record(job)
        assert process.returncode == code and actual['state'] == state, (job, actual, stderr, output(job), stdout)
        assert 'populated 0' in (cg / 'fortis-sandboxes' / job / 'cgroup.events').read_text()
        assert actual['finishedAtMs'] >= actual['createdAtMs']
        checks.append(job)
        return actual

    call('init')
    root_mode = Path('/').stat().st_mode & 0o777
    try:
        os.chmod('/', root_mode | 0o002)  # Disposable overlay root, never the host.
        call('doctor', code=2)
    finally:
        os.chmod('/', root_mode)
    # Overlapping subordinate IDs fail closed before launch.
    Path('/etc/subuid').write_text('fortis-sandbox:1048576:131072\nother:1048576:65536\n')
    call('doctor', code=2)
    Path('/etc/subuid').write_text('fortis-sandbox:1048576:131072\n')
    # Runtime mutation is fail-closed, without running payloads.
    policy.write_text(json.dumps(settings | {'runtimeSha256': '0' * 64}))
    call('doctor', code=2)
    policy.write_text(json.dumps(settings))
    if backend == 'gvisor':
        for name in ('gvisor_sentry', 'gvisor-sentry-prewarmer', 'runsc-fd-parking', 'gvisor-proc-umounter'):
            sidecar = Path(runtime).parent / 'gvisor-bin' / name
            saved = sidecar.with_name(name + '.disabled')
            sidecar.rename(saved)
            try:
                call('doctor', code=2)
            finally:
                saved.rename(sidecar)
        checks.append('missing-required-sidecars-refused')
    no_supervisor = launch('no-supervisor', 'inspect')
    assert no_supervisor.communicate(timeout=10) and no_supervisor.returncode == 2
    assert not (jobs / 'no-supervisor').exists()
    supervisor = subprocess.Popen([binary, str(policy), 'supervise'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end = time.monotonic() + 10
    while not (jobs.parent / 'heartbeat').exists() and time.monotonic() < end:
        time.sleep(.02)
    try:
        job = launch('inspect', 'inspect')
        finish(job, 'inspect', 'succeeded', 0)
        assert 'isolation-ok' in output('inspect')
        assert 'network-namespace=' + os.readlink('/proc/self/ns/net') not in output('inspect')
        assert 'network-namespace=' in output('inspect')
        (root / 'bin/probe').chmod(0o755)
        refused = launch('writable-image', 'inspect'); refused.communicate(timeout=10)
        assert refused.returncode == 2 and not (jobs / 'writable-image').exists()
        (root / 'bin/probe').chmod(0o555)
        finish(launch('closed-stdio', 'inspect', close_stdio=True), 'closed-stdio', 'succeeded', 0)
        assert 'isolation-ok' in output('closed-stdio')
        assert (jobs / 'closed-stdio/owner.lock').stat().st_size == 0
        job = launch('tail', 'tail')
        finish(job, 'tail', 'succeeded', 0)
        assert output('tail').count('tail-line\n') == 2000
        finish(launch('failure', 'fail'), 'failure', 'failed', 1)
        finish(launch('output', 'output', outputLimitBytes=1024), 'output', 'output_limit', 1)
        assert (jobs / 'output/output.log').stat().st_size == 1024
        finish(launch('scratch', 'scratch', scratchLimitMiB=1), 'scratch', 'succeeded', 0)
        assert 'scratch-limit-ok' in output('scratch')
        fork = finish(launch('fork', 'fork'), 'fork', 'task_limit', 1)
        assert fork['taskLimitHits'] > 0
        oom = finish(launch('memory', 'memory'), 'memory', 'oom_killed', 1)
        assert oom['oomKills'] > 0 and oom['memoryPeakBytes'] > 200 * 1024 * 1024
        cpu = launch('cpu', 'cpu', cpuLimitMillicores=100, timeoutSeconds=2)
        wait_for('cpu')
        envelope = cg / 'fortis-sandboxes/cpu'
        assert (envelope / 'cpu.max').read_text().strip() == '10000 100000'
        assert (envelope / 'memory.max').read_text().strip() == str(256 * 1024 * 1024)
        assert (envelope / 'memory.swap.max').read_text().strip() == '0'
        if backend == 'gvisor' and os.environ.get('FORTIS_AUDIT_GVISOR') == '1':
            # Observe actual host processes without ptracing systrap's own tracer.
            # Only this job's cgroup is inspected; optional sidecars must not run.
            flag_contract = False
            end = time.monotonic() + 1.0
            while time.monotonic() < end:
                for tasks in envelope.rglob('cgroup.procs'):
                    for pid in tasks.read_text().split():
                        try:
                            executable = os.readlink('/proc/' + pid + '/exe')
                            observed_executables.add(Path(executable).name)
                            args = Path('/proc/' + pid + '/cmdline').read_bytes().split(b'\0')
                            if all(flag in args for flag in (b'--directfs=false', b'--network=none', b'--oci-seccomp=true',
                                                             b'--netgofer=off', b'--sidecar-release-enforcement-policy=ALWAYS')):
                                flag_contract = True
                        except (FileNotFoundError, ProcessLookupError):
                            pass  # A sampled process may exit between procfs reads.
                time.sleep(.01)
            assert 'gvisor_sentry' in observed_executables and flag_contract, observed_executables
            assert not observed_executables.intersection({'checkpointgofer', 'runsc-metric-server', 'runsc-netgofer', 'containerd-shim-runsc-v1'})
            checks.append('live-executable-and-isolation-flag-audit')
        measured = finish(cpu, 'cpu', 'timed_out', 1)
        assert measured['metricsSampled'] and 50_000 < measured['cpuUsageUsec'] < 1_000_000
        assert 'nr_throttled 0\n' not in (envelope / 'cpu.stat').read_text()
        watchdog = launch('watchdog', 'cpu', timeoutSeconds=2); wait_for('watchdog')
        watchdog.send_signal(signal.SIGSTOP)
        try:
            end = time.monotonic() + 6
            while 'populated 0' not in (cg / 'fortis-sandboxes/watchdog/cgroup.events').read_text() and time.monotonic() < end:
                time.sleep(.1)
            assert (jobs / 'watchdog/expired').exists()
            assert 'populated 0' in (cg / 'fortis-sandboxes/watchdog/cgroup.events').read_text()
        finally:
            watchdog.send_signal(signal.SIGCONT)
        finish(watchdog, 'watchdog', 'timed_out', 1)
        cancel = launch('cancel', 'cpu'); wait_for('cancel')
        call('stop', 'cancel'); finish(cancel, 'cancel', 'cancelled', 1)
        call('stop', 'cancel')  # Idempotent terminal cancellation.
        killed = launch('orphan', 'cpu'); wait_for('orphan')
        killed.kill(); killed.communicate(timeout=10)
        end = time.monotonic() + 15
        while record('orphan')['state'] not in ('interrupted', 'cleanup_failed') and time.monotonic() < end:
            time.sleep(.1)
        assert record('orphan')['state'] == 'interrupted'
        assert 'populated 0' in (cg / 'fortis-sandboxes/orphan/cgroup.events').read_text()
        checks.append('manager-crash-recovered')
        first = launch('first', 'cpu'); wait_for('first')
        second = launch('second', 'cpu'); wait_for('second')
        refused = launch('over-capacity', 'inspect'); refused.communicate(timeout=10)
        assert refused.returncode == 2 and not (jobs / 'over-capacity').exists()
        duplicate = launch('first', 'inspect'); duplicate.communicate(timeout=10)
        assert duplicate.returncode == 2
        supervisor.terminate(); supervisor.communicate(timeout=40)
        assert supervisor.returncode == 0
        finish(first, 'first', 'cancelled', 1)
        finish(second, 'second', 'cancelled', 1)
        # Restart does not rerun immutable job IDs, and reconstructs durable history.
        supervisor = subprocess.Popen([binary, str(policy), 'supervise'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(.3)
        assert len(json.loads(call('list').stdout)) >= 12
        # Deliberate corruption must not race the live watchdog's fail-closed scan.
        supervisor.terminate(); supervisor.communicate(timeout=40)
        assert supervisor.returncode == 0
        bad = jobs / 'failure/record'
        saved = bad.read_bytes(); bad.write_bytes(saved.replace(b'failed', b'forged'))
        call('status', 'failure', code=2); bad.write_bytes(saved)
        checks += ['admission', 'duplicate-id', 'supervisor-shutdown', 'history', 'record-checksum', 'runtime-hash', 'subordinate-id-overlap', 'writable-image', 'untrusted-root']
    finally:
        if supervisor.poll() is None:
            supervisor.terminate()
        stdout, stderr = supervisor.communicate(timeout=40)
        assert supervisor.returncode == 0, (stdout, stderr)
    print(json.dumps({'backend': backend, 'runtime': subprocess.check_output([runtime, '--version'], text=True).splitlines()[0],
                      'checks': checks, 'passed': True,
                      'observedRuntimeExecutables': sorted(observed_executables),
                      'packageProfile': json.loads((Path(runtime).parent / 'fortis-gvisor-package.json').read_text())['profile'] if backend == 'gvisor' else None}, sort_keys=True))


if __name__ == '__main__':
    main()
