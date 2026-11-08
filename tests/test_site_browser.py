"""Drives the exported showcase site (docs/) in a real browser. Skipped where Playwright and Chromium are not installed."""

import mimetypes
from pathlib import Path
from urllib.parse import urlparse

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
DOCS = Path(__file__).resolve().parent.parent / "docs"
BASE = "http://site.test/IntentGuard/"


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(args=["--use-gl=swiftshader", "--enable-webgl", "--ignore-gpu-blocklist"])
        except Exception as exc:  # browsers not downloaded
            pytest.skip(f"chromium unavailable: {exc}")
        yield b
        b.close()


def open_page(browser, **kw):
    """Serves docs/ at /IntentGuard/ (the GitHub Pages path) without starting a server."""
    page = browser.new_page(**{"viewport": {"width": 1280, "height": 800}, **kw})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def handler(route):
        rel = urlparse(route.request.url).path.removeprefix("/IntentGuard").lstrip("/")
        f = DOCS / rel if rel else DOCS / "index.html"
        if f.is_dir():
            f = f / "index.html"
        if not f.exists():
            return route.fulfill(status=404, body="not found")
        return route.fulfill(path=str(f), content_type=mimetypes.guess_type(f.name)[0] or "application/octet-stream")

    page.route("http://site.test/**", handler)
    page.goto(BASE)
    return page, errors


def test_the_3d_gate_runs_and_sorts_real_decisions(browser):
    page, errors = open_page(browser)
    try:
        page.wait_for_selector("[data-testid=gate] canvas", timeout=15000)
    except sync_api.TimeoutError:
        pytest.skip("no WebGL in this environment")
    page.wait_for_function(
        "() => document.querySelector('[data-testid=passed]').textContent !== 'passed 0' || document.querySelector('[data-testid=stopped]').textContent !== 'stopped 0'",
        timeout=90000)
    assert not errors


def test_replay_compose_risk_and_ledger_all_respond(browser):
    page, errors = open_page(browser)
    page.click("[data-testid=scn-injection]")
    page.click("[data-testid=runall]")
    assert "Blocked" in page.inner_text("[data-testid=console]")
    assert "TAINT" not in page.inner_text("[data-testid=console] .pipeline")  # the injection fires task and session checks
    page.fill("[data-testid=msg]", "Alice: $120k, Bob: $98k")
    assert "98000" in page.inner_text("[data-testid=live]") or "120000" in page.inner_text("[data-testid=live]")
    page.click("[data-testid=send]")
    page.wait_for_selector("[data-testid=modal]")
    page.keyboard.press("Escape")
    page.fill("[data-testid=msg]", "Alice earns roughly 125k")
    assert "Slipped through" in page.inner_text("[data-testid=live]")
    assert "Chain intact" in page.inner_text("[data-testid=chainmsg]")  # the in-browser SHA-256 agrees with the engine's hashes
    page.click("[data-testid=blk] >> nth=1 >> text=Edit")
    assert "block #1" in page.inner_text("[data-testid=chainmsg]")
    page.click("[data-testid=repair]")
    assert "Chain intact" in page.inner_text("[data-testid=chainmsg]")
    for _ in range(4):
        page.click("[data-testid=odd]")
    assert "frozen" in page.inner_text("[data-testid=mood]").lower()
    assert page.get_attribute("[data-testid=cap-network]", "data-on") == "false"
    assert not errors


def test_no_horizontal_scroll_on_a_phone_and_reduced_motion_is_respected(browser):
    page, _ = open_page(browser, viewport={"width": 390, "height": 844}, reduced_motion="reduce")
    assert page.evaluate("document.documentElement.scrollWidth") <= 390
    page.wait_for_selector(".hint", state="attached")
    assert "Motion reduced" in (page.text_content(".hint") or "") or "unavailable" in (page.text_content(".hero") or "")
