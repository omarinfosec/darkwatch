"""Core crawl rules: only the target onion host is fetched, Referer only
within that host, max_pages / max_depth, the per-domain circuit breaker and
the stop event. No network: fetch() is replaced by an in-memory site.
Run: pytest darkwatch/tests/
"""

import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import darkwatch as dw  # noqa: E402

HOST = "a" * 56 + ".onion"
TARGET = f"http://{HOST}"
OTHER = "http://" + "b" * 56 + ".onion"


def _page(*hrefs):
    return "<html><body>" + "".join(
        f'<a href="{h}">x</a>' for h in hrefs) + "</body></html>"


class _Resp:
    def __init__(self, html):
        self.text = html
        self.headers = {"Content-Type": "text/html"}


class _Db:
    def record_url_error(self, url_id, cat): pass
    def clear_url_errors(self, url_id): pass


def _crawler(site, max_pages=100, max_depth=5, breaker=3):
    """A DarkWebCrawler with only what crawl_site() needs. `site` maps URL
    -> html; a URL missing from it fails like an unreachable page."""
    c = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    c.max_pages = max_pages
    c.max_depth = max_depth
    c.domain_fail_breaker = breaker
    c.retries = 1
    c.proxies = {}
    c.scan_pdfs = False
    c.db = _Db()
    c.stealth = type("S", (), {"delay": lambda self: None})()
    c.save_page = lambda url, html: None
    c.scan_page = lambda url_id, url, html: 1
    c.fetched = []

    def fetch(url, session=None, referer=None):
        c.fetched.append((url, referer))
        if url in site:
            return _Resp(site[url]), None
        return None, "timeout"
    c.fetch = fetch
    return c


def test_only_the_target_host_is_fetched():
    site = {
        TARGET: _page(
            "/about",                               # same host, relative
            f"{TARGET}/contact",                    # same host, absolute
            f"{OTHER}/x",                           # another onion
            f"http://www.{HOST}/sub",               # a subdomain is another host
            f"http://zz{HOST}/padded",              # ends with the target
            f"http://{'c' * 56}.onion.evil.com/x",  # .onion inside a clearnet name
            f"http://{HOST}@evil.com/",             # target as userinfo
            "http://x.onion@evil.com/",
            "https://example.com/",                 # clearnet
        ),
        f"{TARGET}/about": _page(),
        f"{TARGET}/contact": _page(),
    }
    c = _crawler(site)
    pages, findings = c.crawl_site(1, TARGET)
    fetched = {u for u, _ in c.fetched}
    assert fetched == {TARGET, f"{TARGET}/about", f"{TARGET}/contact"}
    assert (pages, findings) == (3, 3)


def test_seed_has_no_referer_and_children_keep_same_host_referer():
    site = {
        TARGET: _page("/a"),
        f"{TARGET}/a": _page("/b"),
        f"{TARGET}/b": _page(),
    }
    c = _crawler(site)
    c.crawl_site(1, TARGET)
    assert c.fetched == [
        (TARGET, None),
        (f"{TARGET}/a", TARGET),
        (f"{TARGET}/b", f"{TARGET}/a"),
    ]


def test_max_pages_is_respected():
    site = {TARGET: _page(*[f"/p{i}" for i in range(10)])}
    site.update({f"{TARGET}/p{i}": _page() for i in range(10)})
    c = _crawler(site, max_pages=4)
    pages, _ = c.crawl_site(1, TARGET)
    assert pages == 4
    assert len(c.fetched) == 4


def test_max_depth_is_respected():
    # TARGET -> /d1 -> /d2 -> /d3: a straight chain, one hop per depth.
    site = {
        TARGET: _page("/d1"),
        f"{TARGET}/d1": _page("/d2"),
        f"{TARGET}/d2": _page("/d3"),
        f"{TARGET}/d3": _page(),
    }
    c = _crawler(site, max_depth=1)
    assert c.crawl_site(1, TARGET)[0] == 2
    assert [u for u, _ in c.fetched] == [TARGET, f"{TARGET}/d1"]
    # The per-call override wins over the configured depth.
    c = _crawler(site, max_depth=1)
    assert c.crawl_site(1, TARGET, max_depth=2)[0] == 3
    c = _crawler(site, max_depth=5)
    assert c.crawl_site(1, TARGET, max_depth=0)[0] == 1


def test_circuit_breaker_stops_after_consecutive_failures():
    # Seed succeeds, every child fails: 1 + breaker fetches, then abort.
    site = {TARGET: _page(*[f"/dead{i}" for i in range(6)])}
    c = _crawler(site, breaker=3)
    assert c.crawl_site(1, TARGET) == (1, 1)
    assert len(c.fetched) == 1 + 3


def test_preset_stop_event_returns_zero():
    c = _crawler({TARGET: _page("/a")})
    stop = threading.Event()
    stop.set()
    assert c.crawl_site(1, TARGET, stop_event=stop) == (0, 0)
    assert c.fetched == []


@pytest.mark.parametrize("href", [
    f"{OTHER}/x",
    f"https://{HOST}/tls",
    f"http://{HOST.upper()}/caps",
])
def test_extract_links_keeps_onion_hosts(href):
    c = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    assert c.extract_links(_page(href), TARGET + "/") == {href}


@pytest.mark.parametrize("href", [
    f"http://{'c' * 56}.onion.evil.com/x",
    f"http://{HOST}@evil.com/",
    "http://x.onion@evil.com/",
    "https://example.com/?u=x.onion",
    f"ftp://{HOST}/file",
    "mailto:someone@x.onion",
    "http://[::1",                         # unparsable: skipped, no exception
])
def test_extract_links_drops_non_onion_hosts(href):
    c = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    assert c.extract_links(_page(href, "/ok"), TARGET + "/") == {f"{TARGET}/ok"}
