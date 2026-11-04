"""Saved-page sanitizer: the Content-Security-Policy that comes first in
<head>, <base> removal, URL-attribute normalisation, remote loads from
img/video/audio/source/svg image/CSS (protocol-relative "//" included), the
older script/iframe/form/on* stripping, and the sanitize_saved_html switch.
The browser test opens a sanitized page from file:// and checks it makes no
request; it is skipped when no Playwright Chromium is installed
(DARKWATCH_TEST_CHROMIUM names another Chromium binary to use).
Run: pytest darkwatch/tests/
"""

import http.server
import os
import sys
import threading

import pytest
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import darkwatch as dw  # noqa: E402

CSP = ("default-src 'none'; img-src data:; media-src data:; font-src data:; "
       "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")


def _clean(html, **cfg):
    return BeautifulSoup(dw.HTMLSanitizer.sanitize(html, cfg), "lxml")


def _first_head_child(soup):
    return next(c for c in soup.head.children if getattr(c, "name", None))


# ── Content-Security-Policy ──────────────────────────────────────────────────

@pytest.mark.parametrize("html", [
    ('<html><head><meta charset="utf-8"><title>t</title>'
     '<link rel="stylesheet" href="x.css"></head><body>x</body></html>'),
    "<html><body><p>no head</p></body></html>",
    "<p>fragment</p>",
    "plain text",
    "<!doctype html><p>doctype, no head</p>",
    "",
])
def test_csp_is_first_child_of_head(html):
    soup = _clean(html)
    meta = _first_head_child(soup)
    assert meta.name == "meta"
    assert meta["http-equiv"] == "Content-Security-Policy"
    assert meta["content"] == CSP
    assert len(soup.find_all("head")) == 1
    assert soup.head.parent.name == "html"
    # The policy precedes everything else in the document.
    assert soup.find(True, recursive=True) is soup.html
    assert soup.html.find(True) is soup.head


def test_csp_also_with_every_strip_option_off():
    soup = _clean("<p>x</p>", strip_scripts=False, strip_iframes=False,
                  strip_objects=False, strip_tracking=False)
    assert _first_head_child(soup)["content"] == CSP


def test_page_csp_meta_cannot_come_first():
    # A page's own (looser) policy stays behind ours; browsers enforce both.
    soup = _clean('<html><head><meta http-equiv="Content-Security-Policy" '
                  'content="default-src *"></head></html>')
    metas = soup.head.find_all("meta")
    assert metas[0]["content"] == CSP


# ── <base> and URL attributes ───────────────────────────────────────────────

def test_base_is_removed():
    soup = _clean('<html><head><base href="http://evil.example/">'
                  '</head><body><base href="//evil.example/">'
                  '<a href="x">x</a></body></html>')
    assert soup.find("base") is None
    assert soup.a["href"] == "x"


def test_base_is_removed_with_strip_tracking_off():
    assert _clean('<base href="http://evil.example/">x',
                  strip_tracking=False).find("base") is None


@pytest.mark.parametrize("value", [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "  javascript:alert(1)",
    "\x01\x02javascript:alert(1)",
    "java\tscript:alert(1)",
    "java\nscr\ript:alert(1)",
    "&#x09;javascript:alert(1)",
    "jav&#x0A;ascript:alert(1)",
    "&#x6A;avascript:alert(1)",
    "vbscript:msgbox(1)",
    " VBScript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD4=",
    " data:application/xhtml+xml,x",
    "DATA:text/plain,hello",
    "da\tta:text/html,x",
])
@pytest.mark.parametrize("tag,attr", [
    ("a", "href"), ("area", "href"), ("img", "src"), ("video", "poster"),
    ("audio", "src"), ("source", "src"), ("blockquote", "cite"),
    ("table", "background"),
])
def test_dangerous_url_schemes_are_dropped(tag, attr, value):
    soup = _clean(f'<html><body><{tag} {attr}="{value}">x</{tag}>'
                  "</body></html>")
    assert not soup.find(tag).has_attr(attr)


def test_dangerous_url_in_svg_image_and_xlink_is_dropped():
    soup = _clean('<svg><a xlink:href="javascript:alert(1)"><text>x</text></a>'
                  '<image href=" javascript:alert(1)"/></svg>')
    assert not soup.find("a").has_attr("xlink:href")
    assert not soup.find("image").has_attr("href")


def test_data_images_and_relative_urls_are_kept():
    png = "data:image/png;base64,iVBORw0KGgo="
    soup = _clean(f'<a href="/next?p=2">n</a><a href="#top">t</a>'
                  f'<img src="{png}"><img src="pics/a.png">')
    assert soup.find_all("a")[0]["href"] == "/next?p=2"
    assert soup.find_all("a")[1]["href"] == "#top"
    assert soup.find_all("img")[0]["src"] == png
    assert soup.find_all("img")[1]["src"] == "pics/a.png"


# ── remote loads ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("src", [
    "http://evil.example/p.png",
    "https://evil.example/p.png",
    "//evil.example/p.png",
    " //evil.example/p.png",
    "\\\\evil.example\\p.png",
    "HTTP://evil.example/p.png",
    "http:evil.example/p.png",
])
def test_img_remote_src_is_rewritten(src):
    img = _clean(f'<img src="{src}">').img
    assert img["src"] == "[EXTERNAL_IMAGE_REMOVED]"
    assert img["data-original-src"] == src


@pytest.mark.parametrize("html,tag,attr", [
    ('<video src="//evil.example/v.mp4"></video>', "video", "src"),
    ('<video poster="//evil.example/p.png"></video>', "video", "poster"),
    ('<video poster="http://evil.example/p.png"></video>', "video", "poster"),
    ('<audio src="https://evil.example/a.mp3"></audio>', "audio", "src"),
    ('<audio src="//evil.example/a.mp3"></audio>', "audio", "src"),
    ('<video><source src="//evil.example/v.webm"></video>', "source", "src"),
    ('<picture><source srcset="//evil.example/a.webp 1x"></picture>',
     "source", "srcset"),
    ('<img srcset="a.png 1x, https://evil.example/b.png 2x">', "img", "srcset"),
    ('<video><track src="//evil.example/t.vtt"></video>', "track", "src"),
    ('<svg><image href="//evil.example/i.png"/></svg>', "image", "href"),
    ('<svg><image xlink:href="http://evil.example/i.png"/></svg>',
     "image", "xlink:href"),
    ('<link rel="stylesheet" href="//evil.example/s.css">', "link", "href"),
])
def test_media_remote_loads_are_moved_aside(html, tag, attr):
    el = _clean(html).find(tag)
    assert not el.has_attr(attr)
    assert "evil.example" in el["data-original-" + attr.replace(":", "-")]


def test_relative_media_and_data_srcset_are_kept():
    soup = _clean('<video poster="p.png"><source src="v.webm"></video>'
                  '<img srcset="data:image/png;base64,AAAA 1x">')
    assert soup.video["poster"] == "p.png"
    assert soup.source["src"] == "v.webm"
    assert soup.img["srcset"] == "data:image/png;base64,AAAA 1x"


@pytest.mark.parametrize("css", [
    '@import "//evil.example/x.css";',
    "@import 'https://evil.example/x.css';",
    "@import url(//evil.example/x.css);",
    "body { background: url(//evil.example/b.png) }",
    'body { background: url("http://evil.example/b.png") }',
    "@font-face { src: url('//evil.example/f.woff') }",
    "@import url( //evil.example/x.css);",
    "body { background: url(\n  'https://evil.example/b.png' ) }",
])
def test_css_remote_loads_are_removed(css):
    soup = _clean(f"<html><head><style>{css}</style></head></html>")
    assert "/* REMOVED */" in soup.style.string
    assert "//evil.example" not in soup.style.string


@pytest.mark.parametrize("style", [
    "background:url(//evil.example/c.png)",
    "background:url( //evil.example/c.png)",
    "background:url(\t\"http://evil.example/c.png\" )",
])
def test_style_attribute_remote_url_is_removed(style):
    p = _clean(f"<p style='{style}'>x</p>").p
    assert "evil.example" not in p["style"]


# ── existing stripping ──────────────────────────────────────────────────────

def test_scripts_frames_objects_forms_and_handlers_still_stripped():
    soup = _clean(
        '<html><head><script src="//evil.example/s.js"></script>'
        '<meta http-equiv="refresh" content="0;url=http://evil.example/">'
        '<link rel="preload" href="//evil.example/x">'
        '<link rel="stylesheet" href="local.css"></head>'
        '<body onload="alert(1)"><noscript>n</noscript><script>alert(1)</script>'
        '<iframe src="//evil.example/"></iframe><object data="x"></object>'
        # libxml2 nests what follows an <embed> inside it.
        '<div><embed src="x"></div><applet code="x"></applet>'
        '<form action="//evil.example/"><input name="q"><button>go</button>'
        '<textarea></textarea><select></select></form>'
        '<p onclick="alert(1)" OnMouseOver="alert(1)">text</p>'
        '<img src="t.png" width="1" height="1"><img src="ok.png" width="10">'
        '</body></html>')
    for name in ("script", "noscript", "iframe", "object", "embed", "applet",
                 "form", "input", "button", "textarea", "select"):
        assert soup.find(name) is None, name
    assert soup.body.attrs == {}
    assert soup.p.attrs == {}
    assert soup.p.get_text() == "text"
    assert not any(m.get("http-equiv", "").lower() == "refresh"
                   for m in soup.find_all("meta"))
    assert [link["href"] for link in soup.find_all("link")] == ["local.css"]
    assert [img["src"] for img in soup.find_all("img")] == ["ok.png"]


def test_frameset_is_stripped():
    soup = _clean("<frameset><frame src=\"//evil.example/\"></frameset>")
    assert soup.find("frameset") is None and soup.find("frame") is None
    assert _first_head_child(soup)["content"] == CSP


# ── sanitize_saved_html ──────────────────────────────────────────────────────

def _saver(tmp_path, sanitize):
    c = dw.DarkWebCrawler.__new__(dw.DarkWebCrawler)
    c.save_pages = True
    c.loot_dir = str(tmp_path)
    os.makedirs(os.path.join(c.loot_dir, "pages"))
    c.security_cfg = {"sanitize_saved_html": sanitize}
    c.sanitizer = dw.HTMLSanitizer()
    return c


RAW = ('<html><body><script>alert(1)</script>'
       '<img src="//evil.example/p.png"></body></html>')


def _saved(tmp_path):
    (name,) = os.listdir(os.path.join(tmp_path, "pages"))
    with open(os.path.join(tmp_path, "pages", name)) as f:
        return f.read()


def test_save_page_sanitizes_by_default(tmp_path):
    _saver(tmp_path, True).save_page("http://x.onion/", RAW)
    out = _saved(tmp_path)
    assert "Content-Security-Policy" in out
    assert "<script" not in out


def test_sanitize_saved_html_false_saves_page_unchanged(tmp_path):
    _saver(tmp_path, False).save_page("http://x.onion/", RAW)
    assert _saved(tmp_path) == RAW


# ── a real browser ───────────────────────────────────────────────────────────

class _Hits(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Hits.hits.append(self.path)
        self.send_response(404)
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *args):
        pass


def _vectors(origin):
    """One page with every load vector, pointing at `origin` (host:port)."""
    o = origin
    return f"""<!doctype html><html><head>
<base href="http://{o}/base/">
<link rel="stylesheet" href="//{o}/link.css">
<style>@import "//{o}/import.css"; body {{ background: url(//{o}/bg.png) }}
@font-face {{ font-family: f; src: url(http://{o}/font.woff) }}
p {{ font-family: f }}</style>
<meta http-equiv="refresh" content="0;url=http://{o}/refresh">
</head><body>
<p style="background-image:url('//{o}/inline.png')">text</p>
<img src="//{o}/img.png"><img src="http://{o}/img2.png">
<img srcset="//{o}/srcset.png 1x">
<img src="relative.png">
<picture><source srcset="//{o}/picture.png"><img src="x.png"></picture>
<video src="//{o}/video.mp4" poster="//{o}/poster.png" autoplay></video>
<video autoplay><source src="http://{o}/source.mp4"></video>
<audio src="//{o}/audio.mp3" autoplay></audio>
<svg width="10" height="10"><image href="//{o}/svg.png" width="10" height="10"/>
<image xlink:href="http://{o}/xlink.png" width="10" height="10"/></svg>
<script>fetch("http://{o}/script")</script>
<img src="x" onerror="fetch('http://{o}/onerror')">
<iframe src="http://{o}/iframe"></iframe>
<object data="http://{o}/object"></object>
<form action="http://{o}/form" id="f"><input name="q"></form>
</body></html>"""


def _browser_requests(tmp_path, html):
    """Open `html` from file:// in headless Chromium; return the paths the
    local server saw and the non-file URLs the browser requested."""
    sync_api = pytest.importorskip("playwright.sync_api")
    _Hits.hits = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Hits)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    origin = f"127.0.0.1:{srv.server_address[1]}"
    page_file = tmp_path / "page.html"
    page_file.write_text(html(origin))
    requested = []
    try:
        with sync_api.sync_playwright() as p:
            try:
                browser = p.chromium.launch(executable_path=os.environ.get(
                    "DARKWATCH_TEST_CHROMIUM") or None)
            except Exception as e:
                pytest.skip(f"no Playwright Chromium: {e}")
            try:
                page = browser.new_page()
                page.on("request", lambda r: requested.append(r.url))
                page.goto(page_file.as_uri())
                page.wait_for_timeout(1500)
            finally:
                browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return list(_Hits.hits), [u for u in requested
                              if not u.startswith(("file:", "data:"))]


def test_browser_makes_no_request_for_sanitized_page(tmp_path):
    # Control: the raw page does reach the server, so the check can fail.
    hits, _ = _browser_requests(tmp_path, _vectors)
    assert hits, "the unsanitized page made no request; test is broken"

    hits, requested = _browser_requests(
        tmp_path, lambda o: dw.HTMLSanitizer.sanitize(_vectors(o), {}))
    assert hits == []
    assert requested == []
