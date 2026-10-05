"""Starts a fake gate script and waits until it accepts connections.

Every probe that needs a local gate (fakegate.py, tlsgate.py) starts it here,
so the wait and its failure report live in one place. A gate that does not
come up says WHY: whether the process exited (and with what stderr) or was
still running when the wait gave up, and how long the wait took.
"""
import os, socket, subprocess, sys, tempfile, time

WAIT_SECONDS = 10.0


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start(script, args, label="fake gate"):
    """Runs `python3 <script> <port> <args...>`; returns (process, port) once
    the port accepts a connection. Raises SystemExit naming the cause if not."""
    port = free_port()
    err = tempfile.TemporaryFile()
    t0 = time.monotonic()
    proc = subprocess.Popen([sys.executable, script, str(port)] + list(args),
                            stdout=subprocess.DEVNULL, stderr=err)
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), 0.25).close()
            err.close()
            return proc, port
        except OSError as e:
            last = e
        code = proc.poll()
        waited = time.monotonic() - t0
        if code is not None or waited > WAIT_SECONDS:
            break
        time.sleep(0.02)
    if code is None:
        proc.terminate()
        proc.wait()
        state = f"still running after {waited:.1f}s"
    else:
        state = f"exited with code {code} after {waited:.1f}s"
    err.seek(0)
    tail = err.read()[-4000:].decode("utf-8", "replace")
    err.close()
    raise SystemExit(
        f"{label} did not come up on 127.0.0.1:{port}: {state}; "
        f"last connect error: {last!r}; python {sys.version.split()[0]} "
        f"({sys.executable})\n--- gate stderr ---\n{tail}")
