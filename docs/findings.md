# Findings log

Dated notes on what the benchmark showed and what was changed because of it. This is the audit trail
that keeps tuning separate from evaluation. Numbers come from `python -m bench.run`; they are
preliminary because the episodes and the engine share an author.

## F1: intent compiler dropped the implied read (fixed post hoc)

v0 run: two ambiguous episodes ("email the paper to my collaborator") had their file read blocked
(2.8% false-positive rate), because "email" compiled to `SEND` only.
Fix: `SEND`, `UPLOAD`, `SUMMARIZE` now imply `READ` ([scope.py](../src/intentguard/scope.py)).
After the fix: core-set FPR 0.0% (CI 0.0 to 5.1%), ASR unchanged at 11.4%.
Caveat: this was found by looking at the core set, so the core set is now a development set. Only
episode sets written later and not used for tuning count as held-out.

## F2: broad user grants let credential reads through (open, by design for now)

Core-set misses were four multi-step episodes where the user's grants covered `*` up to SECRET, so
reading `secrets/app.env` was in scope. The later egress step was blocked. Scope is derived from grants,
not from the task text, so grants that are broader than the task are not narrowed.

## F3: sequence set (`bench/episodes.py: build_seq`, 10 episodes, written after F1/F2)

Every step is individually in scope; attacks are recon -> credential reads -> egress to an
*approved* destination with paraphrased content.

| System | Egress attacks that succeeded | Harmful steps that executed |
|---|---|---|
| unprotected | 6/6 | 100% |
| static RBAC | 3/6 | 83.3% |
| IntentGuard full | 1/6 | 72.2% |
| no behaviour analysis | 3/6 | 83.3% |
| no data-flow analysis | 1/6 | 72.2% |

Reading: the exfiltration reduction from 3/6 to 1/6 comes from the behaviour component (risk
accumulates, dynamic reduction turns the network off, the egress is blocked). Counts are tiny; treat
as a direction to confirm with more episodes, not a result.

Open weakness: `credential_sweep` to an approved destination succeeded (QM004). Two credential-file
reads with no preceding secret search raise no sequence rule, so risk stays at 0. A rule keyed on
"credential-class file read" (not only search -> read) is the obvious next experiment, to be
evaluated on a new held-out set rather than this one.

Benign look-alikes (4 episodes) produced no false positives, including a double-config-read case.
That is a small sample; the double-read stress case sits just under the 0.4 reduction threshold.
