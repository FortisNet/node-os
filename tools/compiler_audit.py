#!/usr/bin/env python3
"""Record actual native compiler invocations; never substitutes a successful exit."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    logfile, compiler, *arguments = sys.argv[1:]
    sources = [str(Path(arg).resolve()) for arg in arguments
               if Path(arg).suffix in ('.c', '.cpp', '.S', '.s') and Path(arg).is_file()]
    result = subprocess.run([compiler, *arguments], check=False)
    record = {'directory': os.getcwd(), 'arguments': [compiler, *arguments],
              'sources': {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sources},
              'returncode': result.returncode}
    with open(logfile, 'a') as output:
        fcntl.flock(output, fcntl.LOCK_EX)
        output.write(json.dumps(record) + '\n')
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
