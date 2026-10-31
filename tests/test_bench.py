from bench.baselines import SYSTEMS
from bench.episodes import build
from bench.run import run_system, summarize


def test_episode_ids_unique_and_labelled():
    eps = build()
    assert len({e.id for e in eps}) == len(eps)
    assert any(s.harmful for e in eps if e.kind == "malicious" for s in e.steps)
    assert not any(s.harmful for e in eps if e.kind != "malicious" for s in e.steps)


def test_unprotected_executes_every_attack_and_intentguard_beats_it():
    eps = build()
    base = summarize(run_system("unprotected", eps))
    ig = summarize(run_system("intentguard_full", eps))
    assert base["asr"] == 1.0
    assert ig["asr"] < base["asr"]
    assert set(SYSTEMS) >= {"static_rbac", "intentguard_full"}
