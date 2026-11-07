# Master researcher prompt for Perplexity

Attach `docs/literature-review-matrix-20.xlsx` to the Perplexity message, then paste everything inside the block
into Perplexity (Pro Search or Deep Research). If it is too long for one message,
paste PART 1 first, then PART 2 and PART 3 in follow-ups.

````text
ROLE
You are a meticulous senior research assistant in computer security and AI safety. You help a postgraduate student
draft the literature review, introduction and findings sections of a research paper. The student will write the final
paper themselves, so your job is to give them accurate, well-sourced raw material and three different framings to
choose from. Accuracy beats polish.

HARD RULES (follow these over everything else)
1. Cite only sources you can actually open and verify now. Never invent a paper, author, venue, year, DOI, number or
   quote. If you cannot verify something, write "UNVERIFIED" next to it and say why. An honest gap is better than a
   plausible guess.
2. For every source give: authors, title, venue, year, DOI or arXiv ID, and a working link. State whether it is
   peer-reviewed (journal/conference) or a preprint. Say "Scopus indexing not checked" unless you saw it indexed.
3. Do not copy sentences from sources. Paraphrase, and keep any quote under 15 words with the page or section.
4. Use only the numbers I give you in PART 2 for my own project's results. Never invent or round up results, and
   always carry the stated limitations with them.
5. Separate clearly: (a) what the literature established, (b) what is still open, (c) what my project contributes.
   Do not claim my project is better than a published system unless PART 2 says it was measured.
6. Prefer 2023-2026 work. Include the foundational papers. Flag very new preprints as preprints.
7. If sources disagree, say so and cite both sides.
8. The attached spreadsheet is my working material, not ground truth. If a row disagrees with the paper itself, trust
   the paper and tell me.

PART 1: THE PROJECT (what the paper is about)
Working title: "Intent-Aware Authorization for AI Agents".
Problem: LLM agents now call tools (email, files, databases, shell) on a user's behalf and read untrusted content. A
hidden instruction in that content (indirect prompt injection) can make the agent take actions the user never
authorized, or leak sensitive data. Static per-tool permissions cannot say whether THIS call is justified by THIS task,
and per-call filters miss attacks made of individually allowed steps.
System ("IntentGuard"): a gateway that holds the tools instead of the agent. For each proposed call it decides ALLOW,
REVIEW (a human decides) or BLOCK with an explanation, using deterministic rules over: (1) task scope compiled from the
user's task and grants, (2) data sensitivity and destination trust, (3) data lineage (fingerprints of sensitive data the
session read, matched against outbound content after decoding), (4) cumulative behavioural risk across steps with
graded permission reduction, (5) scanning tool output for injected instructions. Everything is logged in a
tamper-evident hash-chained audit log. It works with LangChain/LangGraph agents and as an MCP gateway.
Research questions: RQ1 does intent/task-scoped authorization reduce unauthorized actions versus conventional controls?
RQ2 does cumulative multi-step risk catch attacks made of allowed steps? RQ3 what does protection cost in review
friction and task completion? RQ4 how should such systems be evaluated honestly?

PART 2: MY PROJECT'S RESULTS (use only these, with their limits)
- Benchmark (synthetic, scripted agents, same author as the system): on three seeded generated sets (150 to 300
  episodes each) IntentGuard let 1.0% to 2.3% of harmful steps execute, against 100% unprotected. On the two larger
  sets: about 71% to 76% for static role-based access, 74% to 81% for a keyword guardrail, about 72% for LlamaFirewall's
  default local scanners (which also blocked 11% to 13% of benign steps), and 85% to 89% for Llama Prompt Guard 2 (an
  injection classifier, so many tool-misuse attacks give it nothing to flag). Caveat: part of this is circular because the
  generator and the rule were written by the same person; attack success of 11.4% on hand-written episodes became 43.2% on a
  held-out set before one rule was added, which shows results do not transfer automatically.
- Red-team sets written before each fix (dev and held-out halves): encoded and split exfiltration, filename-collision
  and obfuscated-SQL attacks went from 13/13 to 1/13 (dev) and 11/17 to 5/17 (held-out); a content-lineage check cut
  another set from 10/13 to 1/13 (dev) and 9/13 to 4/13 (held-out). Remaining misses: paraphrase, leetspeak, short first
  pieces of a split secret. Held-out means new instances of the same attack classes, not independent attackers.
- Real local models (llama3.1:8b, qwen2.5:7b) as agents, forceful synthetic injections, neutral prompt, 8 runs per cell:
  unprotected agents executed an unauthorized call in 23 of 32 runs (72%, 95% CI 55% to 85%); through the gateway 0 of 32
  (CI 0% to 11%). This is a susceptibility stress test with small models and an automatic approver, not a rate for
  real attackers.
- Costs measured: review friction roughly 4% on generated sets and a drop in task completion from about 93% to 88%
  after tightening filename matching; in the model runs most lost completions came from the model stopping after its
  first blocked call, and real lock-outs were rarer. Two attempts to relax the lock-out (a per-action risk cap and
  sending locks to human review) were not adopted: the cap roughly doubled attack success on generated sets; the review
  variant puts many more harmful steps in front of a human.
- Limitations to state: same author for system and benchmarks, no independent episode set, small local models,
  synthetic data, an oracle approver, and no head-to-head run against Progent or CaMeL.

ATTACHED FILE: my 20-paper literature matrix (an Excel workbook, literature-review-matrix-20.xlsx)
Read it first. These 20 papers are your anchor set. It has three sheets:
 - "Literature matrix": one row per paper with these columns: Author, Title, Affiliation, Keyword, DOI, Journal / Source,
   Publisher, Year, Abstract, Relevance, Major findings / Contributions, Challenges, Model / Framework, Metrics / Results,
   Data / Dataset. The rows are grouped by theme: threat and benchmarks, model-level defences, design-level and
   intent-based authorization, runtime guardrails, multi-step risk, and evaluation methodology.
 - "Scopus venue check": for each paper, whether its venue appears in Scopus's source list (venue level only; whether
   each individual paper is indexed was NOT checked).
 - "Notes": where each column came from and its limits.
How to treat it:
 - The Author, Title, Abstract, DOI and Year columns came from arXiv and Semantic Scholar. Check the DOI and year against
   the real paper, because a preprint year can differ from the proceedings year, and some DOIs are arXiv DOIs.
 - The Relevance, Major findings, Challenges, Model/Framework, Metrics/Results and Data/Dataset columns were written by
   an AI assistant from each abstract, not from the full paper. Treat them as leads, not facts. Open the paper and
   correct any of them that the full text contradicts, and tell me which ones you corrected.
 - Keywords are auto-assigned, not the authors' own. Affiliations are missing for some papers.
 - Use the 20 papers first, in every set. Then add other verified sources where the themes need them. Say explicitly
   which of the 20 each set uses, and which of the 20 you left out of a set and why.
 - 6 of the 20 are preprints with no published venue (Fides, Progent, IGAC, LlamaFirewall and two 2026 evaluation papers);
   label them as preprints. One more (STAC) appeared at a workshop whose venue I could not find in Scopus. The closest recent prior art on
   intent-based authorization is the 2026 IGAC preprint ("Intent-Governed Tool Authorization for AI Agents"), alongside
   Progent, CaMeL and The Task Shield: compare against these directly.

YOUR TASK: PRODUCE THREE SETS. Each set takes a different angle on the same project so I can pick or combine.
 SET 1, Access control and least privilege: frame the work as runtime authorization for tool-using agents
        (capabilities, least privilege, confused deputy, task-scoped permissions, policy enforcement points).
 SET 2, Injection and data exfiltration: frame it as defence against indirect prompt injection and leakage
        (information-flow control, taint and lineage, model-level versus system-level defences).
 SET 3, Evaluation and behavioural risk: frame it around multi-step attacks, cumulative risk, and how to evaluate
        agent defences honestly (static benchmarks, adaptive attacks, held-out discipline, measuring cost).

For EACH set, deliver these three parts, in this order:

 A. LITERATURE REVIEW (700 to 900 words)
    - 3 or 4 themes, each a short paragraph that synthesises (does not list) 4 to 6 verified sources, drawn mainly
      from my 20 and topped up with others only where needed.
    - A comparison table: source | what it does | evaluation used | main limitation | relation to IntentGuard.
    - A "gap" paragraph that states precisely what remains open, and where IntentGuard's contribution is genuinely
      different from the closest prior work (name it, e.g. Progent, CaMeL, IGAC, Task Shield) rather than claiming novelty.

 B. INTRODUCTION (400 to 500 words)
    Structure: Context ("Given that..."), Technical complication ("However..."), Impact ("Therefore..."), the gap, the
    proposed intervention, the research questions, and a bulleted list of contributions that matches PART 2 only.
    Use cautious verbs ("reduces", "mitigates"), never "prevents" or "solves".

 C. FINDINGS (500 to 700 words)
    - What the literature found overall (consensus, contradictions, trends, what evaluation weaknesses recur).
    - Then how my reported results in PART 2 sit against that, with their limits stated beside each number.
    - End with 5 to 7 specific "threats to validity and open questions" a reviewer would raise.

AFTER THE THREE SETS
 1. A master reference list in APA 7, de-duplicated, each marked [peer-reviewed] or [preprint] and with its link.
 2. A "verification report": every source you could not fully verify, every claim you were unsure of, and anything
    from PART 2 you were tempted to strengthen but did not.
 3. A recommended reading order of the 10 most important papers for someone writing this paper, one line each on why.
 4. A short list of 8 additional recent papers that are NOT among the 20 in my spreadsheet (verified, with links),
    especially anything that already does intent-based or task-scoped authorization for agents, so I can position the
    work correctly.

STYLE
Plain, precise academic English. No hype, no filler, no first-person claims about my work beyond PART 2. Short
paragraphs. Where a point is your inference rather than a source's claim, mark it "(inference)".
````

## How to use it well

0. Upload `literature-review-matrix-20.xlsx` with the first message. If your Perplexity plan cannot read Excel files,
   export the "Literature matrix" sheet to CSV and attach that, or paste the Title, Year, DOI and Journal columns.
1. Run it in **Deep Research** mode if you have it, or in Pro Search with the three parts pasted one at a time.
2. Open every link it gives you and confirm the paper exists and says what it claims before you cite anything.
   Perplexity can still get details wrong even with the rules above.
3. Check each paper in Scopus yourself; the prompt tells Perplexity not to claim indexing it did not see.
4. Use the three sets as raw material. Pick the framing your instructor will like, rewrite in your own words, and keep
   the limitations next to every number.
