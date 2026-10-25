"""Offline witness: deny, count and fail every network egress attempt.

Installed first in the CLI parent, the spawned coordinator and every worker, before
any analysis work. Audit hooks cannot be removed, so a runner process stays
egress-denied, and a hook that fails to deny is a refused run, never a silent one.
"""
import http.client
import socket
import sys
import urllib.request

WITNESS_ATTEMPTS = 4
DENIED_EVENTS = frozenset({
    "socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
    "socket.sendto", "socket.sendmsg", "urllib.Request",
})

_events: list[str] = []
_installed = False


class EgressDenied(PermissionError):
    """The audit hook refused a network egress operation."""

    def __init__(self, event: str) -> None:
        super().__init__("egress_denied:" + event)
        self.event = event


def _audit(event: str, _arguments: tuple[object, ...]) -> None:
    if event in DENIED_EVENTS:
        _events.append(event)
        raise EgressDenied(event)


def install() -> bool:
    """Install the process audit hook once; True when this call installed it."""
    global _installed
    if _installed:
        return False
    sys.addaudithook(_audit)
    _installed = True
    return True


def violations() -> tuple[str, ...]:
    """The denied egress events this process recorded, in arrival order."""
    return tuple(_events)


def probe() -> int:
    """Attempt one operation per denied family; return the denied-and-counted count."""
    before = len(_events)
    try:
        socket.getaddrinfo("localhost", 9)
    except OSError:
        pass
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect(("localhost", 9))
    except OSError:
        pass
    finally:
        connection.close()
    try:
        urllib.request.urlopen("http://localhost:9/", timeout=1)
    except OSError:
        pass
    client = http.client.HTTPConnection("localhost", 9, timeout=1)
    try:
        client.connect()
    except OSError:
        pass
    finally:
        client.close()
    return len(_events) - before
