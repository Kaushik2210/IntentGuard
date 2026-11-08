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


def test_the_site_data_matches_the_engine():
    published = json.loads((ROOT / "web" / "src" / "data" / "site-data.json").read_text(encoding="utf-8"))
    # the audit chain holds random action ids, so it differs on every run; it is checked for validity instead
    from intentguard.audit import AuditLog
    log = AuditLog()
    log.entries = published.pop("chain")
    assert log.verify() == (True, None)
    published.pop("build")
    fresh = json.loads(json.dumps(site.make_data(), ensure_ascii=False))
    fresh.pop("chain")
    assert published == fresh, "web/src/data/site-data.json is stale: run `python site/build_site.py`"


def test_the_published_page_exists_and_loads_nothing_from_elsewhere():
    html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert "IntentGuard" in html and "/_next/" in html, "docs/ has no exported site: run `npm run publish:docs` in web/"
    assert not re.search(r'<(script|link|img|iframe)[^>]+(src|href)="https?://', html)


CASES = ["alice,120000", "Alice: $120k, Bob: $98k", "alice makes 120,000 a year", "Bob is paid ninety eight thousand",
         "Alice: one hundred and twenty thousand", "Alice earns 120 thousand dollars", "Alice earns roughly 125k",
         "Alice earns more than Bob", "Alice gana ciento veinte mil", "QWxpY2UsMTIwMDAw", "ORUGS4ZANFZSA5DJNZSS4MRRGAYDAMBA",
         "416c6963652c313230303030", "nyvpr,120000 obo,98000", "00099,000cile", "4L1C3,12OOOO", "al1c3 3arn5 12O OOO",
         "Meeting at 10:30 in room 4; budget of 50000 is approved.", "Done: 2 rows read, nothing unusual in 2024.",
         "alice120000bob98000", "A L I C E , 1 2 0 0 0 0 B O B", "%61lice%2C120000", "nine thousand", "twenty-five thousand",
         "1.5m and 98,000", "98 000", "v1.2.98000", "hello world this is just a long ordinary sentence"]


def test_the_javascript_port_agrees_with_the_python_engine():
    import shutil
    import subprocess

    from intentguard.engine import _decodings, _fp, _grams, _leet, _numbers, _overlaps
    from intentguard.mock_env import FILES
    if shutil.which("node") is None:
        pytest.skip("node is not installed")
    src = FILES["hr/salary.xlsx"][0]
    grams = _grams(src, 12) | {_fp(f"#{n}") for n in _numbers(src)}

    def py_hit(text):
        views = _decodings(text)
        views += [r for v in views for r in _leet(v)]
        return _overlaps(views, grams, 12, True)

    module = (ROOT / "web" / "src" / "lib" / "lineage.ts").as_uri()
    script = (f"import({json.dumps(module)}).then(m=>{{const src={json.dumps(src)},cases={json.dumps(CASES)};"
              "console.log(JSON.stringify(cases.map(c=>[c,m.check(c,src).hit])));})")
    run = subprocess.run(["node", "--no-warnings", "-e", script], capture_output=True, text=True, cwd=ROOT)
    if run.returncode != 0 and "Unknown file extension" in run.stderr:
        pytest.skip("this node cannot run TypeScript directly (needs 22.18 or newer)")
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout)
    disagree = [(c, py_hit(c), js) for c, js in out if py_hit(c) != js]
    assert not disagree, disagree
    assert sum(py_hit(c) for c in CASES) >= 10  # the list really exercises the matcher


def test_the_audit_chain_shown_on_the_page_is_the_real_one(data):
    from intentguard.audit import AuditLog
    log = AuditLog()
    log.entries = [dict(e) for e in data["chain"]]
    assert log.verify() == (True, None) and len(data["chain"]) >= 4
    log.entries[1]["payload"] += " "
    assert log.verify() == (False, 1)

