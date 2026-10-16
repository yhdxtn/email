#!/usr/bin/python3 -I
"""Install root-owned as /usr/local/libexec/astrogate-mail-helper.
No imports from the current directory, shell, arbitrary paths, environment or commands.
"""
import os
import re
import subprocess
import sys


def main(argv: list[str]) -> int:
    if os.geteuid() != 0 or len(argv) != 3:
        return 64
    action, target = argv[1:]
    if action == "reload" and target in {"postfix", "dovecot", "opendkim"}:
        command = ["/usr/bin/systemctl", "reload", target]
    elif action in {"queue-retry", "queue-delete"} and re.fullmatch(r"[A-Za-z0-9]{5,32}", target):
        command = ["/usr/sbin/postqueue", "-i", target] if action == "queue-retry" else ["/usr/sbin/postsuper", "-d", target]
    else:
        return 64
    try:
        return 0 if subprocess.run(command, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}).returncode == 0 else 1
    except (OSError, subprocess.TimeoutExpired):
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
