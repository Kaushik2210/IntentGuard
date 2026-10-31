import json

import pytest

from bench.external import load_external
from bench.run import run_system, summarize

FIX = __import__("pathlib").Path(__file__).parent / "fixtures"


def test_external_episodes_load_and_run():
    eps = load_external(FIX)
    assert [e.id for e in eps] == ["E-ex1", "E-ex2"]
    s = summarize(run_system("intentguard_full", eps))
    assert s["asr"] == 0.0 and s["fpr_block"] == 0.0


def test_bad_episode_is_rejected(tmp_path):
    (tmp_path / "bad.json").write_text(json.dumps({"id": "x", "kind": "evil", "category": "c",
                                                    "task": "t", "grants": {}, "steps": []}))
    with pytest.raises(ValueError):
        load_external(tmp_path)
