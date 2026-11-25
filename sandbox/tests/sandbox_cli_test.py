#!/usr/bin/env python3
"""Portable CLI contract checks; execution is tested separately with real runtimes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='fortis-sandbox-cli-') as directory:
        root = Path(directory)
        spec = root / 'spec.json'
        policy = root / 'policy.json'
        request = {'schemaVersion': 1, 'id': 'job-a', 'image': 'approved',
                   'args': ['/bin/probe', 'private argument']}
        settings = {'schemaVersion': 1, 'runtimeSha256': 'a' * 64}
        spec.write_text(json.dumps(request))
        policy.write_text(json.dumps(settings))

        def call(*args, success=True):
            result = subprocess.run([binary, *map(str, args)], capture_output=True,
                                    text=True, timeout=10)
            assert (result.returncode == 0) == success, result
            assert 'private argument' not in result.stderr
            return result

        valid = json.loads(call('validate', spec).stdout)
        assert valid == {'valid': True, 'schemaVersion': 1, 'id': 'job-a'}
        plan = json.loads(call('plan', policy, spec).stdout)
        assert plan['root']['readonly'] is True
        process = plan['process']
        assert process['args'] == request['args']
        assert process['user'] == {'uid': 1000, 'gid': 1000}
        assert process['noNewPrivileges'] and not any(process['capabilities'].values())
        assert process['env'] == ['PATH=/usr/bin:/bin', 'HOME=/tmp', 'LANG=C']
        linux = plan['linux']
        assert linux['cgroupsPath'] == '/fortis-sandboxes/job-a/payload'
        assert len(linux['namespaces']) == 7
        resources = linux['resources']
        assert resources['cpu'] == {'period': 100000, 'quota': 100000}
        assert resources['memory'] == {'limit': 268435456, 'swap': 268435456}
        assert resources['pids']['limit'] == 64
        assert all(m['type'] in ('tmpfs', 'proc') for m in plan['mounts'])
        assert linux['seccomp']['defaultAction'] == 'SCMP_ACT_ALLOW'
        denied = {name for rule in linux['seccomp']['syscalls'] for name in rule['names']}
        assert {'ptrace', 'mount', 'bpf', 'clone', 'clone3', 'io_uring_setup'} <= denied
        for field, value in [('network', True), ('mounts', []), ('env', []),
                             ('isolation', 'process'), ('cpuLimitMillicores', 2**64),
                             ('args', ['relative'])]:
            spec.write_text(json.dumps(request | {field: value}))
            call('validate', spec, success=False)
        spec.write_text(json.dumps(request))
        policy.write_text(json.dumps(settings | {'cpuBudgetMillicores': 500}))
        call('plan', policy, spec, success=False)
        call('validate', spec, 'unexpected', success=False)
        call('plan', policy, success=False)
        call(root / 'missing-policy', 'doctor', success=False)
    print('Sandbox CLI schema, OCI policy and fail-closed contracts passed.')


if __name__ == '__main__':
    main()
