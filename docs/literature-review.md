# Literature survey and worksheet draft: IntentGuard

Prepared 2026-11-01 for the Postgraduate Research Worksheet (Research Methodology).

## 0. Read this first (honest limits)

- **I cannot query Scopus.** It needs institutional login and a licensed API key. The 50 papers below come from an open paper index (arXiv-centred) plus my own knowledge of the field. They are ranked by *relevance to this research problem and by how foundational they are*, not by Scopus citation counts.
- **Check each paper in Scopus yourself.** Many 2025-26 items are preprints and may not be Scopus-indexed yet. Use the search string in section 1 and keep only the ones Scopus returns. The "Venue" column is from my memory for the well-known papers and is marked `verify`. Confirm it before citing. Do not cite anything from this file without opening the paper.
- **Novelty warning.** Several 2026 papers (items 9, 10, 11, 12, 13, 14 below) overlap with your "intent-based authorization" claim. Your literature review must position IntentGuard against them. Do not claim "no one has done intent-based authorization".

## 1. Scopus search string (run this yourself)

```
TITLE-ABS-KEY ( ( "LLM agent*" OR "AI agent*" OR "agentic" OR "autonomous agent*" OR "tool-using" OR "tool-augmented" )
  AND ( "prompt injection" OR "access control" OR authorization OR "least privilege" OR "information flow" OR "taint"
        OR "data exfiltration" OR guardrail* OR "runtime enforcement" OR "policy enforcement" ) )
  AND PUBYEAR > 2022
```

Then: sort by *Cited by (highest)*, limit to Conference Paper and Article, and export the top 50 to a reference manager. Run a second pass with `"intent" AND "authorization"` and a third with `"multi-step" AND "tool call" AND ( risk OR anomaly )`.

## 2. Fifty candidate papers

IDs are arXiv IDs returned by the search tool. Group labels map to your six differentiators.

### A. Problem definition, attacks and threat landscape
| # | Paper | ID | Venue (verify) |
|---|---|---|---|
| 1 | Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection (Greshake et al.) | arXiv:2302.12173 | AISec 2023 |
| 2 | Benchmarking and Defending Against Indirect Prompt Injection Attacks on LLMs (BIPIA) | arXiv:2312.14197 | KDD 2025 |
| 3 | The Emerged Security and Privacy of LLM Agent: A Survey with Case Studies | arXiv:2407.19354 | ACM Computing Surveys |
| 4 | Navigating the Risks: A Survey of Security, Privacy, and Ethics Threats in LLM-Based Agents | arXiv:2411.09523 | preprint |
| 5 | SoK: The Attack Surface of Agentic AI - Tools and Autonomy | arXiv:2603.22928 | preprint |
| 6 | A Systematic Survey of Security Threats and Defenses in LLM-Based AI Agents: A Layered Attack Surface Framework | arXiv:2604.23338 | preprint |
| 7 | Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges | arXiv:2510.23883 | preprint |
| 8 | The Attack and Defense Landscape of Agentic AI: A Comprehensive Survey | arXiv:2603.11088 | preprint |

### B. Intent-based and task-scoped authorization (closest prior art, differentiator 1)
| # | Paper | ID |
|---|---|---|
| 9 | Intent-Governed Tool Authorization for AI Agents (IGAC) | arXiv:2606.22916 |
| 10 | Before the Tool Call: Deterministic Pre-Action Authorization for Autonomous AI Agents (Open Agent Passport) | arXiv:2603.20953 |
| 11 | Progent: Securing AI Agents with Privilege Control | arXiv:2504.11703 |
| 12 | MiniScope: Authorizing Agents with Least-Privilege Permissions | arXiv:2512.11147 |
| 13 | Delegated Authorization for Agents Constrained to Semantic Task-to-Scope Matching | arXiv:2510.26702 |
| 14 | AC4A: Access Control for Agents | arXiv:2603.20933 |
| 15 | AgentGuard: An Attribute-Based Access Control Framework for Tool-Use LLM-Based Agent | arXiv:2605.28071 |
| 16 | Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework | arXiv:2601.11893 |
| 17 | ToolFence: Fine-Grained Authorization for Secure Tool-Using LLM Agents | arXiv:2609.37196 |
| 18 | AIRGuard: Guarding Agent Actions with Runtime Authority Control | arXiv:2605.28914 |
| 19 | ActGov: Governing LLM Agent Actions via Policy-Constrained Validation | arXiv:2609.24446 |
| 20 | Capability Gates Are Not Authorization: Confused-Deputy Failures in LLM Agent Frameworks | arXiv:2606.28679 |

### C. Information flow, taint and exfiltration (differentiator 4)
| # | Paper | ID |
|---|---|---|
| 21 | Defeating Prompt Injections by Design (CaMeL) | arXiv:2503.18813 |
| 22 | Securing AI Agents with Information-Flow Control (Fides) | arXiv:2505.23643 |
| 23 | System-Level Defense against Indirect Prompt Injection Attacks: An Information Flow Control Perspective | arXiv:2409.19091 |
| 24 | Permissive Information-Flow Analysis for Large Language Models | arXiv:2410.03055 |
| 25 | Ghost in the Agent: Redefining Information Flow Tracking for LLM Agents (NeuroTaint) | arXiv:2604.23374 |
| 26 | An AI Agent Execution Environment to Safeguard User Data (GAAP) | arXiv:2604.19657 |
| 27 | Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents | arXiv:2604.04035 |
| 28 | Simple Prompt Injection Attacks Can Leak Personal Data Observed by LLM Agents During Task Execution | arXiv:2506.01055 |
| 29 | Silent Egress: When Implicit Prompt Injection Makes LLM Agents Leak Without a Trace | arXiv:2602.22450 |
| 30 | Securing Multi-Tool AI Agent Chains With Dynamic, Real-Time Compositional Policies | arXiv:2607.03423 |

### D. Multi-step, behavioural and cumulative-risk detection (differentiators 2 and 3)
| # | Paper | ID |
|---|---|---|
| 31 | STAC: When Innocent Tools Form Dangerous Chains for LLM Agents | arXiv:2509.25624 |
| 32 | AgentHazard: A Benchmark for Evaluating Harmful Behavior in Computer-Use Agents | arXiv:2604.02947 |
| 33 | Unsafer in Many Turns: Benchmarking and Defending Multi-Turn Safety Risks in Tool-Using Agents | arXiv:2602.13379 |
| 34 | Enforcing Benign Trajectories: A Behavioral Firewall for Structured-Workflow AI Agents | arXiv:2604.26274 |
| 35 | AGATE: Provenance-Based Runtime Defense Against Compositional Attacks on LLM Agents | arXiv:2609.30830 |
| 36 | AgentTrust: Runtime Safety Evaluation and Interception for AI Agent Tool Use | arXiv:2605.04785 |
| 37 | Semantic Intent Fragmentation: A Single-Shot Compositional Attack on Multi-Agent AI Pipelines | arXiv:2604.08608 |
| 38 | Trust No Tool: Evaluating and Defending LLM Agents under Untrusted Tool Feedback | arXiv:2605.17453 |

### E. Guardrails, runtime enforcement and explainable oversight (differentiators 3 and 5)
| # | Paper | ID |
|---|---|---|
| 39 | LlamaFirewall: An open source guardrail system for building secure AI agents | arXiv:2505.03574 |
| 40 | AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents | arXiv:2503.18666 |
| 41 | ShieldAgent: Shielding Agents via Verifiable Safety Policy Reasoning | arXiv:2503.22738 |
| 42 | Governance Architecture for Autonomous Agent Systems: Threats, Framework, and Engineering Practice | arXiv:2603.07191 |
| 43 | The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents | arXiv:2412.16682 |
| 44 | MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents | arXiv:2502.05174 |

### F. Benchmarks and evaluation methodology (differentiator 6)
| # | Paper | ID |
|---|---|---|
| 45 | AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents | arXiv:2406.13352 |
| 46 | InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents | arXiv:2403.02691 |
| 47 | Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents | arXiv:2410.02644 |
| 48 | Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents | arXiv:2606.26479 |
| 49 | Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks? | arXiv:2510.05244 |
| 50 | Ignored, Not Refused: What Low Prompt-Injection Success Rates Hide in Small Tool-Using Agents | arXiv:2610.23254 |

Not in the 50 but worth reading as the model-level defence line: Spotlighting (arXiv:2403.14720), StruQ (arXiv:2402.06363), SecAlign (arXiv:2410.05451), Meta-SecAlign (arXiv:2507.02735).

## 3. The best five for the literature review

Chosen because together they cover the problem, the evaluation standard, the two strongest design-based defences, and the baseline you actually ran.

1. **Greshake et al. (2023), Not what you've signed up for** (#1). Defines indirect prompt injection and the data-theft and exfiltration impacts. It is the citation for your "Given that..." sentence.
2. **Debenedetti et al. (2024), AgentDojo** (#45). The standard benchmark. Your independent-benchmark argument (differentiator 6) must be positioned against it.
3. **Debenedetti et al. (2025), Defeating Prompt Injections by Design (CaMeL)** (#21). Strongest published design-level defence. It separates control flow from untrusted data and uses capabilities against exfiltration. Your closest comparison for data lineage.
4. **Shi et al. (2025), Progent** (#11). Least-privilege policy over tool names and arguments, generated from the user task, with monotonic narrowing. This is the closest published relative of your task-scope compiler and permission ladder, so it is the paper you must differentiate from.
5. **Chennabasappa et al. (2025), LlamaFirewall** (#39). The open-source guardrail you used as the baseline. It is also the "conventional control" side of H1.

Strong alternates: Fides (#22) if you want the information-flow angle, IGAC (#9) if you want the most recent intent-based paper.

## 4. What the survey tells you about your gap

- Task-scoped, least-privilege authorization is **already published** (Progent, MiniScope, IGAC, OAP, AC4A). Intent-to-scope compilation alone is not novel.
- Information-flow and taint control for agents is **already well developed** (CaMeL, Fides, GAAP, NeuroTaint). Taint alone is not novel.
- Defensible gaps from the survey: (a) **cumulative, cross-session risk with graded permission reduction** as a combined mechanism (partly touched by AGATE, SafeAgent and PSG-Agent, so check them closely); (b) **evaluation discipline**: dev vs held-out vs fresh seeds, paired ablations and an independent episode set (papers #48-#50 show the field distrusts static benchmarks, which supports this); (c) the **honest negative result** that scripted-injection scores do not transfer to held-out sets.
- Suggested framing: *"Existing runtime defences enforce task scope or track taint in isolation; we study their combination with cumulative behavioural risk and report where each mechanism fails under independent evaluation."*

## 5. Worksheet draft (fill in your own words; this is a starting point)

**Subfield:** AI/ML security (agent safety) and Systems.

**Paper title (options):**
- Intent-Aware and Behavioural Authorization for Autonomous AI Agents: A Runtime Framework for Reducing Unauthorized Tool Execution and Sensitive Data Exfiltration
- Shorter: Intent-Aware Runtime Authorization for Tool-Using AI Agents

**1. Context ("Given that..."):** Given that LLM-based agents now call tools (email, files, databases, shell) on a user's behalf and process untrusted content such as emails and web pages [Greshake 2023; AgentDojo 2024]...

**2. Complication and impact ("However... Therefore..."):** However, current controls grant static permissions and judge each action in isolation, so an injected or misaligned agent can chain individually permitted actions (read a sensitive file, then send it out) [STAC 2025; AgentHazard 2026]. Therefore sensitive data can leak and unauthorized actions can run even when per-call filters pass, and reported defences are often validated only on static benchmarks [Adaptive Evaluation 2026].

**3. Proposed intervention:** IntentGuard, a gateway that is the only holder of the tools. It compiles the user's task into a scope, scores cumulative risk across steps, tracks data lineage, reduces permissions as risk grows, and sends risky actions to a human with an explanation. Every decision goes into a tamper-evident log.

**Part 2: Core flow**
- *Input(s):* user task text and grants, each proposed tool call (tool, arguments, resource, destination), tool outputs, resource and destination catalogue (classification, trust).
- *Core mechanism:* deterministic policy engine: task scope check, taint/egress rules, sequence rules, cumulative risk with a permission-reduction ladder, injection scan of outputs.
- *Output(s):* ALLOW, REVIEW or BLOCK with the rules fired and a plain-language explanation; updated session capabilities; audit record.

**Baselines (and why fair):** unprotected agent, static RBAC, keyword guardrail, and LlamaFirewall local scanners (Prompt Guard 2 pending). They run on the same episodes with the same ground-truth labels and the same harness. Also compare against Progent and CaMeL *conceptually* (their code and settings differ, so state that a direct run is future work unless you actually run them).

**Part 3: Three metrics** (all measured in the repo):
1. Attack success rate (unauthorized action executed) with Wilson 95% intervals.
2. Task completion on benign episodes, plus false-block and review-friction rates.
3. Decision latency (p50 and p95 per call), and exfiltration rate.

**Final remarks and relevance:** Agent deployments are growing faster than their authorization controls. A deterministic, explainable gateway can be audited in a way that model-based filters cannot. Report limits plainly: single author episodes, a 3B model that did not follow injections, and gaps found by the adversarial sets (see `docs/findings.md`).

## 6. Writing templates (drafting aids, not text to submit)

- *Opening:* "LLM-based agents increasingly act through tools, which turns prompt injection from a content problem into an authorization problem [1, 2]."
- *Gap:* "Prior runtime defences either bound privileges per task [11, 12, 9] or track data flow [21, 22], but evaluate them mainly on static benchmarks [48, 49]. It remains unclear how they behave when combined with cumulative behavioural risk under independent evaluation."
- *Contribution list:* "(1) a runtime authorization gateway combining ...; (2) IntentGuardBench with dev, held-out and fresh episode sets and paired ablations; (3) an audit of where each mechanism fails."
- *Limitations paragraph:* state same-author episode bias, template intent compiler, small LLM study, no Scopus-ranked comparison to Progent and CaMeL runs.

## 7. Next steps for you

1. Run the Scopus string, keep only indexed items, and replace my "verify" venues with the real ones.
2. Read the five core papers fully, then abstracts and intros of #9-#14 to settle the novelty claim with your instructor.
3. Reword all worksheet text yourself. Submit your own prose.
