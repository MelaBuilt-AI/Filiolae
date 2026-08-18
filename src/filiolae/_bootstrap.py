"""Held exec bootstrap used by :mod:`filiolae.supervisor`.

This module is internal. It establishes a READY/GO handshake so governed target
code cannot execute between the supervisor's initial and post-spawn freeze checks.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    ready_fd = int(os.environ.pop("FILIOLAE_READY_FD"))
    go_fd = int(os.environ.pop("FILIOLAE_GO_FD"))
    command = sys.argv[1:]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        return 64
    os.write(ready_fd, b"READY\n")
    os.close(ready_fd)
    token = os.read(go_fd, 1)
    os.close(go_fd)
    if token != b"G":
        return 75
    os.execvpe(command[0], command, os.environ)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
