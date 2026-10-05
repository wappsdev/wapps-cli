"""The fake gates' process: the server they run, and how a probe starts one.

Every probe that needs a local gate (fakegate.py, tlsgate.py) starts it with
`start`, so the wait and its failure report live in one place. A gate that does
not come up says WHY: whether the process exited (and with what stderr) or was
still running when the wait gave up, and how long the wait took.
"""
import socket, socketserver, subprocess, sys, tempfile, time
from http.server import HTTPServer

WAIT_SECONDS = 10.0


class Server(HTTPServer):
    """`HTTPServer` without the reverse DNS lookup in its `server_bind`.

    `HTTPServer.server_bind` calls `socket.getfqdn(host)` between bind(2) and
    listen(2). On the hosted macOS runner that lookup of 127.0.0.1 took about
    35 s, and a connect to the bound but not yet listening port timed out, so
    every probe failed with "fake gate did not come up" (gateup.py reproduces
    it). `server_name` only feeds CGI/WSGI environments, which no gate has, so
    the bound address stands in for it."""

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


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
