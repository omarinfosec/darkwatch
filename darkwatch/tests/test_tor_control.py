"""The Tor ControlPort client (dw_tor) and the crawler's NEWNYM rotation,
against a fake ControlPort (the `fake_controlport` fixture in conftest.py)."""

import logging
import socket

import pytest

import darkwatch as dw
import dw_tor

NEWNYM_OK = b"250 OK\r\n250 OK\r\n250 closing connection\r\n"
WRONG_PASSWORD = (b"515 Authentication failed: Password did not match "
                  b"HashedControlPassword value from configuration\r\n")


def _crawler(port, password="ctl-pw", host="127.0.0.1"):
    c = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    c.newnym_between_sites = True
    c.tor_control_host = host
    c.tor_control_port = port
    c.tor_control_password = password
    return c


def test_newnym_sends_authenticate_and_signal(fake_controlport):
    srv = fake_controlport(lambda req: NEWNYM_OK)
    dw_tor.newnym("127.0.0.1", srv.port, "ctl-pw")
    assert srv.requests == [b'AUTHENTICATE "ctl-pw"\r\n'
                            b"SIGNAL NEWNYM\r\nQUIT\r\n"]


def test_newnym_wrong_password_raises_515(fake_controlport):
    srv = fake_controlport(lambda req: WRONG_PASSWORD)
    with pytest.raises(dw_tor.ControlPortError, match="515"):
        dw_tor.newnym("127.0.0.1", srv.port, "wrong")


def test_newnym_needs_a_250_for_the_signal(fake_controlport):
    """Authenticated, but the SIGNAL was refused or never answered."""
    srv = fake_controlport(lambda req: b"250 OK\r\n552 Unrecognized signal\r\n")
    with pytest.raises(dw_tor.ControlPortError, match="552"):
        dw_tor.newnym("127.0.0.1", srv.port, "pw")
    srv.reply = lambda req: b"250 OK\r\n"
    with pytest.raises(dw_tor.ControlPortError):
        dw_tor.newnym("127.0.0.1", srv.port, "pw")


def test_newnym_times_out_when_tor_never_answers(fake_controlport):
    srv = fake_controlport(lambda req: None)
    with pytest.raises(OSError):
        dw_tor.newnym("127.0.0.1", srv.port, "pw", timeout=0.3)


def test_password_quotes_and_backslashes_are_escaped(fake_controlport):
    srv = fake_controlport(lambda req: NEWNYM_OK)
    dw_tor.newnym("127.0.0.1", srv.port, 'a"b\\c')
    assert srv.requests[0].startswith(b'AUTHENTICATE "a\\"b\\\\c"\r\n')


def test_password_with_a_line_break_is_never_sent(fake_controlport):
    srv = fake_controlport(lambda req: NEWNYM_OK)
    with pytest.raises(dw_tor.ControlPortError, match="line break"):
        dw_tor.newnym("127.0.0.1", srv.port, "pw\r\nSIGNAL HALT")
    assert srv.requests == []


def test_control_host_is_resolved_before_connecting(monkeypatch):
    """The sidecar name is resolved first and the connection goes to the
    IP, as with stem (whose from_port only took an IP literal)."""
    seen = []
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda name: seen.append(name) or "192.0.2.7")

    def connect(addr, timeout=None):
        seen.append(addr)
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(OSError):
        dw_tor.newnym("tunnel1", "9051", "pw")
    assert seen == ["tunnel1", ("192.0.2.7", 9051)]


def test_rotate_tor_circuit_uses_the_crawler_settings(fake_controlport):
    srv = fake_controlport(lambda req: NEWNYM_OK)
    assert _crawler(str(srv.port)).rotate_tor_circuit() is True
    assert srv.requests[0].startswith(b'AUTHENTICATE "ctl-pw"\r\nSIGNAL NEWNYM')


def test_rotate_tor_circuit_warns_on_a_wrong_password(fake_controlport, caplog):
    srv = fake_controlport(lambda req: WRONG_PASSWORD)
    with caplog.at_level(logging.WARNING, logger="darkwatch"):
        assert _crawler(srv.port).rotate_tor_circuit() is False
    assert "515" in caplog.text


def test_rotate_tor_circuit_is_quiet_when_controlport_is_closed(caplog):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with caplog.at_level(logging.WARNING, logger="darkwatch"):
        assert _crawler(port).rotate_tor_circuit() is False
    assert caplog.text == ""


@pytest.mark.parametrize("host,port,password", [
    ("127.0.0.1", "abc", "pw"),       # int("abc"): ValueError
    ("127.0.0.1", None, "pw"),        # int(None): TypeError
    (None, 9051, "pw"),               # gethostbyname(None): TypeError
    ("a" * 64 + ".example", 9051, "pw"),  # idna label too long: UnicodeError
    ("127.0.0.1", 9051, 1234),        # non-string password: TypeError
])
def test_rotate_tor_circuit_survives_bad_control_settings(
        monkeypatch, caplog, host, port, password):
    """A bad config.json value must not end the scan: the scan loop calls
    rotate_tor_circuit() outside its per-target try."""
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **kw: pytest.fail("connected"))
    with caplog.at_level(logging.WARNING, logger="darkwatch"):
        assert _crawler(port, password=password,
                        host=host).rotate_tor_circuit() is False
    assert "bad ControlPort settings" in caplog.text


def test_rotate_tor_circuit_off_makes_no_connection(monkeypatch):
    monkeypatch.setattr(dw_tor, "newnym",
                        lambda *a, **kw: pytest.fail("NEWNYM sent"))
    c = _crawler(9051)
    c.newnym_between_sites = False
    assert c.rotate_tor_circuit() is False
