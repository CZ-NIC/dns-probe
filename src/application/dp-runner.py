#!/usr/bin/env python3

import sys
import pathlib
import subprocess

if __name__ == "__main__":
    program = pathlib.Path(sys.argv[0]).parent.absolute() / "dns-probe-@BACKEND@"

    while True:
        proc = subprocess.Popen([str(program), *sys.argv[1:]])
        try:
            completed_process = proc.wait()
            if completed_process != 1:
                sys.exit(completed_process)
        except KeyboardInterrupt:
            completed_process = proc.wait()
            sys.exit(completed_process)
        except:
            proc.kill()
            proc.wait()
            raise
