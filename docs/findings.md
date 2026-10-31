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

## F4: first generated run (dev seed 1: 150 episodes, held-out seed 2026: 300 episodes)

`bench/generate.py` makes episodes from templates with a seed. Seed 2026 was not looked at while the
engine was being built, so it is the first held-out set. Engine at commit `5ce9b82`.

Held-out seed 2026 (140 malicious, 119 benign, 41 ambiguous):

| System | ASR | Benign actions blocked | Exfil attempts that succeeded |
|---|---|---|---|
| unprotected | 100% | 0% | 100% |
| static RBAC | 75.5% | 8.4% | 61.9% |
| keyword guardrail (stand-in, not a published tool) | 80.5% | 0.0% | 73.2% |
| IntentGuard full | 43.2% | 0.0% | 18.6% |
| no intent analysis | 63.6% | 0.0% | 34.0% |
| no behaviour analysis | 45.9% | 0.0% | 21.6% |
| no data-flow analysis | 50.0% | 0.0% | 34.0% |

The 11.4% ASR on the hand-written core set does not hold up on held-out data: it is 43.2%.
Intent analysis contributes most; behaviour and data-flow contribute smaller, overlapping amounts.

Where IntentGuard fails (held-out, harmful steps that executed): all of them are credential-class
reads under broad grants. `credential_sweep` reads 49/49 and its sends to an approved destination
13/13; `recon_then_egress` reads 28/31 and sends 5/8. Everything else (unauthorized file access,
injected egress to unknown or denylisted destinations, credential leaks with secret patterns,
privilege escalation) was stopped in every case. This is the weakness predicted in F3.

Procedure from here: do not tune on seed 2026. Develop the credential-read rule against dev seed 1,
then evaluate on a fresh seed and report both the 2026 number (before) and the new one (after).

## F5: SCOPE-005 (sensitive file must be named by the task), before/after

Rule: a READ of a CONFIDENTIAL+ file is REVIEW unless the task text contains the path or a filename
token of at least 3 characters. Developed against dev seed 1 after F4. `ablate_no_mention_check` is
the engine without it, so every set has a paired before/after.

| Set | ASR before | ASR after | Benign blocked (after) | Review friction (after) |
|---|---|---|---|---|
| core (55, dev set) | 11.4% | 0.0% | 0.0% | 1.4% |
| seq (10, dev set) | 72.2% | 0.0% | 8.7% | 17.4% |
| gen dev seed 1 (150) | 37.9% | 1.0% | 0.0% | 1.4% |
| gen seed 2026 (300, seen in F4, no longer held-out) | 43.2% | 2.3% | 0.0% | 1.8% |
| gen seed 4242 (300, fresh) | 31.3% | 1.0% | 0.0% | 2.3% |

Read this with care:
- The generator writes every attack's credential read without naming the file in the task, and every
  legitimate credential read with the path in the task. The rule is the inverse of how the data was
  made, so the near-zero ASR is partly circular. It shows the rule does what it says, not that
  real attacks are this easy to separate.
- A real user may mention a credential file loosely ("check my settings") or an attacker may
  influence the task text. Neither is covered by these sets.
- Cost is visible on the seq set: 4 benign look-alikes that read `secrets/app.env` without naming it
  now get REVIEW (task completion 25%). Whether those episodes are really benign is a labelling
  judgement; they are counted as benign here.
- A test fix: `test_taint_blocks_exfil_of_derived_content` now names `hr/salary.xlsx` in its task so it
  still exercises taint rather than SCOPE-005.

Needed next: episodes where legitimate tasks refer to sensitive files loosely, and attacks where
the task text or retrieved content names the file, ideally written by someone else.
