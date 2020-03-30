#!/usr/bin/env python3

import sys
import pathlib
import subprocess

if __name__ == "__main__":
    program = pathlib.Path(sys.argv[0]).parent.absolute() / "dns-probe-@BACKEND@"

    while True:
        completed_process = subprocess.run([str(program), *sys.argv[1:]])
        if completed_process.returncode != 1:
            sys.exit(completed_process.returncode)
