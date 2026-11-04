"""
DarkWatch — Tor ControlPort client.

A plain-socket client for the two questions DarkWatch asks Tor's
ControlPort: NEWNYM circuit rotation (the crawler, between targets) and
`status/circuit-established` (the dashboard's Tunnel 1 check). Every request
has a connect and answer deadline, which stem's Controller did not.
"""

import socket
import time


class ControlPortError(ValueError):
    """Tor answered, but not with 250: a wrong password (515), an unknown
    command or key, or the connection closed before every reply came."""


def _quote(password):
    """`password` as a ControlPort QuotedString: backslash and double quote
    escaped. A line break would end the AUTHENTICATE line and start a new
    command, so it is refused instead."""
    if "\r" in password or "\n" in password:
        raise ControlPortError("ControlPort password contains a line break")
    return '"' + password.replace("\\", "\\\\").replace('"', '\\"') + '"'


def request(host, port, password, commands, timeout):
    """Send AUTHENTICATE, each of `commands`, then QUIT, and return the reply
    lines. The host name is resolved first, so the connection goes to the
    sidecar's IP (Docker's internal DNS, not a target lookup).

    `timeout` (seconds) bounds the connect and the whole answer together.
    Raises OSError when the ControlPort can't be reached or doesn't answer
    in time, ControlPortError when a reply is not 250."""
    auth = "AUTHENTICATE " + _quote(password or "")
    lines_out = [auth, *commands, "QUIT"]
    deadline = time.monotonic() + timeout
    addr = socket.gethostbyname(host)
    buf = b""
    with socket.create_connection((addr, int(port)), timeout=timeout) as sock:
        sock.sendall("".join(f"{line}\r\n" for line in lines_out).encode())
        # Tor closes the connection after QUIT (or a failed AUTHENTICATE).
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("ControlPort answer timed out")
            sock.settimeout(left)
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    lines = buf.decode("utf-8", "replace").splitlines()
    # One reply per line sent before QUIT. A reply ends at a line whose
    # fourth character is a space ("250 OK"); "250-key=value" continues it.
    expected = len(lines_out) - 1
    replies = 0
    for line in lines:
        if replies == expected:
            break
        if not line.startswith("250"):
            raise ControlPortError(f"ControlPort refused: {line}")
        if line[3:4] == " ":
            replies += 1
    if replies < expected:
        raise ControlPortError("ControlPort refused: "
                               + (lines[-1] if lines else "no answer"))
    return lines


def newnym(host, port, password, timeout=5):
    """Ask Tor for new circuits (SIGNAL NEWNYM). Raises as request()."""
    request(host, port, password, ["SIGNAL NEWNYM"], timeout)


def circuit_established(host, port, password, timeout=2):
    """Has Tor built a circuit? True for "1", False for "0", the same
    question as the tor container's healthcheck. Raises as request(), and
    ControlPortError when the answer has no circuit-established."""
    for line in request(host, port, password,
                        ["GETINFO status/circuit-established"], timeout):
        if line.startswith("250-status/circuit-established="):
            return line.split("=", 1)[1].strip() == "1"
    raise ControlPortError("ControlPort answer has no circuit-established")
