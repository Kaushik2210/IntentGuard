"""The showcase page (docs/index.html) is generated from the real engine, so it must stay true to it."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_site", ROOT / "site" / "build_site.py")
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)


@pytest.fixture(scope="module")
def data():
    return site.make_data()


def verdicts(data, sid):
    sc = next(s for s in data["scenarios"] if s["id"] == sid)
    return [s["verdict"] for s in sc["steps"]], sc


def test_attacks_are_stopped_before_they_run(data):
    for sid in ("injection", "scope", "leet"):
        v, sc = verdicts(data, sid)
        assert v[-1] == "BLOCK" and not sc["steps"][-1]["ran"] and not sc["steps"][-1]["sent"], sid
    v, sc = verdicts(data, "number")
    assert v[-1] == "REVIEW" and not sc["steps"][-1]["ran"]


def test_normal_work_is_not_slowed_down(data):
    v, _ = verdicts(data, "normal")
    assert v == ["ALLOW", "ALLOW"]


def test_the_page_shows_its_misses_honestly(data):
    assert verdicts(data, "miss")[0] == ["ALLOW", "ALLOW"]  # a documented limit, shown on purpose
    v, sc = verdicts(data, "split")
    assert v[:2] == ["ALLOW", "ALLOW"] and v[2] == "BLOCK" and v[-1] == "QUARANTINE"
    assert sc["steps"][1]["sent"]  # the first piece really did leave


def test_every_blocked_step_names_a_rule(data):
    for sc in data["scenarios"]:
        for s in sc["steps"]:
            if s["verdict"] != "ALLOW":
                assert s["rules"], (sc["id"], s["tool"])


def test_the_published_page_matches_the_engine():
    html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    blob = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1)
    published = json.loads(blob.replace("<\\/", "</"))
    fresh = json.loads(json.dumps(site.make_data(), ensure_ascii=False))
    assert published == fresh, "docs/index.html is stale: run `python site/build_site.py`"


def test_the_page_loads_nothing_from_elsewhere():
    html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert not re.search(r'<(script|link|img|iframe)[^>]+(src|href)="https?://', html)
    assert "__DATA__" not in html and "__BUILD__" not in html and "__RESULTS_COMMIT__" not in html
