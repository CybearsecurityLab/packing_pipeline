#!/usr/bin/env python3
"""Stop a running QEMU and save a named VM snapshot via its HMP monitor socket.

Kept as a file rather than an inline heredoc: the heredoc form swallowed the socket
path argument, so `savevm` silently never executed and the resulting image carried no
snapshot at all (the overlay still grew, which made it look like it had worked).
"""
from __future__ import annotations
import socket, sys, time

sock_path, name = sys.argv[1], sys.argv[2]
# --migrate PATH additionally exports EXTERNAL migration state. That is what the
# per-run resume consumes: a qcow2 internal snapshot lives only in the file holding
# it and is invisible through the backing chain, so it cannot be reached from the
# fresh per-run overlay the harness boots for isolation. An external file can be
# shared read-only by every concurrent run.
migrate_to = None
if "--migrate" in sys.argv:
    migrate_to = sys.argv[sys.argv.index("--migrate") + 1]
s = socket.socket(socket.AF_UNIX)
s.connect(sock_path)
s.settimeout(5)
time.sleep(1)
try:
    s.recv(65536)                       # banner
except Exception:
    pass

def hmp(cmd: str, wait: float) -> str:
    s.sendall((cmd + "\n").encode())
    time.sleep(wait)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except Exception:
        pass
    return out.decode(errors="replace")

print("stop      :", hmp("stop", 3).strip()[-200:])
# savevm on a 4 GB guest writes a lot of state; give it room.
print("savevm    :", hmp(f"savevm {name}", 90).strip()[-300:])
print("snapshots :", hmp("info snapshots", 5).strip()[-400:])
if migrate_to:
    # Uncapped: the default bandwidth limit makes a 4 GB guest take many minutes.
    hmp("migrate_set_parameter max-bandwidth 0", 2)
    print("migrate   :", hmp(f'migrate -d "exec:cat > {migrate_to}"', 5).strip()[-200:])
    for _ in range(60):
        status = hmp("info migrate", 3)
        if "completed" in status:
            print("migrate   : completed")
            break
        if "failed" in status:
            print("migrate   : FAILED", status[-200:])
            break
hmp("quit", 2)
