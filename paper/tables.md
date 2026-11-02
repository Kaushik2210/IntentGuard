# Generated tables (do not edit by hand)

## Main comparison

**gen_fresh_seed4242**: 300 episodes {'benign': 117, 'ambiguous': 44, 'malicious': 139}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| unprotected | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| static_rbac | 70.7 | 58.9 | 5.6 | 0.0 | 83.2 |
| keyword_guardrail_standin | 74.2 | 66.3 | 0.0 | 0.0 | 100.0 |
| llamafirewall_local_scanners | 71.7 | 41.1 | 13.0 | 0.0 | 60.9 |
| llamafirewall_prompt_guard2 | 85.4 | 100.0 | 0.0 | 0.0 | 100.0 |
| intentguard_full | 1.0 | 2.1 | 0.0 | 4.1 | 87.6 |

**gen_heldout_seed2026**: 300 episodes {'benign': 119, 'ambiguous': 41, 'malicious': 140}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| unprotected | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| static_rbac | 75.5 | 61.9 | 8.4 | 0.0 | 76.9 |
| keyword_guardrail_standin | 80.5 | 73.2 | 0.0 | 0.0 | 100.0 |
| llamafirewall_local_scanners | 72.7 | 38.1 | 10.9 | 0.0 | 70.0 |
| llamafirewall_prompt_guard2 | 87.7 | 100.0 | 0.0 | 0.0 | 100.0 |
| intentguard_full | 2.3 | 5.2 | 0.0 | 4.5 | 87.5 |

**adversarial**: 16 episodes {'benign': 0, 'ambiguous': 3, 'malicious': 13}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| unprotected | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| static_rbac | 76.9 | 66.7 | 0.0 | 0.0 | 100.0 |
| keyword_guardrail_standin | 92.3 | 100.0 | 0.0 | 0.0 | 100.0 |
| llamafirewall_local_scanners | 84.6 | 33.3 | 0.0 | 0.0 | 100.0 |
| llamafirewall_prompt_guard2 | 92.3 | 100.0 | 0.0 | 0.0 | 100.0 |
| intentguard_full | 0.0 | 0.0 | 0.0 | 50.0 | 0.0 |

**adversarial2**: 15 episodes {'benign': 0, 'ambiguous': 3, 'malicious': 12}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| unprotected | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| static_rbac | 66.7 | 100.0 | 20.0 | 0.0 | 66.7 |
| keyword_guardrail_standin | 83.3 | 100.0 | 0.0 | 0.0 | 100.0 |
| llamafirewall_local_scanners | 83.3 | 0.0 | 0.0 | 0.0 | 100.0 |
| llamafirewall_prompt_guard2 | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| intentguard_full | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |

**injection_text**: 14 episodes {'benign': 0, 'ambiguous': 4, 'malicious': 10}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| unprotected | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| static_rbac | 60.0 | 66.7 | 0.0 | 0.0 | 100.0 |
| keyword_guardrail_standin | 60.0 | 66.7 | 0.0 | 0.0 | 100.0 |
| llamafirewall_local_scanners | 30.0 | 16.7 | 50.0 | 0.0 | 25.0 |
| llamafirewall_prompt_guard2 | 50.0 | 50.0 | 0.0 | 0.0 | 50.0 |
| intentguard_full | 0.0 | 0.0 | 0.0 | 100.0 | 50.0 |

**xsession_db**: 12 episodes {'benign': 0, 'ambiguous': 5, 'malicious': 7}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| unprotected | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| static_rbac | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| keyword_guardrail_standin | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| llamafirewall_local_scanners | 81.8 | 0.0 | 15.4 | 0.0 | 60.0 |
| llamafirewall_prompt_guard2 | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 |
| intentguard_full | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 |

## Ablations

**gen_fresh_seed4242**: 300 episodes {'benign': 117, 'ambiguous': 44, 'malicious': 139}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| intentguard_full | 1.0 | 2.1 | 0.0 | 4.1 | 87.6 |
| ablate_no_cross_session | 1.0 | 2.1 | 0.0 | 4.1 | 87.6 |
| ablate_no_mention_check | 31.3 | 6.3 | 0.0 | 2.3 | 93.2 |
| ablate_no_intent | 51.5 | 17.9 | 0.0 | 2.3 | 93.2 |
| ablate_no_behaviour | 6.1 | 12.6 | 0.0 | 4.1 | 87.6 |
| ablate_no_dataflow | 8.1 | 16.8 | 0.0 | 4.1 | 87.6 |

**gen_heldout_seed2026**: 300 episodes {'benign': 119, 'ambiguous': 41, 'malicious': 140}, commit `a36fd6f`

| System | ASR % | Exfil % | Benign blocked % | Review friction % | Task completion % |
|---|---|---|---|---|---|
| intentguard_full | 2.3 | 5.2 | 0.0 | 4.5 | 87.5 |
| ablate_no_cross_session | 2.3 | 5.2 | 0.0 | 4.5 | 87.5 |
| ablate_no_mention_check | 43.2 | 18.6 | 0.0 | 1.8 | 95.0 |
| ablate_no_intent | 63.6 | 34.0 | 0.0 | 1.8 | 95.0 |
| ablate_no_behaviour | 9.5 | 21.6 | 0.0 | 4.5 | 87.5 |
| ablate_no_dataflow | 9.1 | 20.6 | 0.0 | 4.5 | 87.5 |


External published guardrail baseline: TO MEASURE (not implemented).
