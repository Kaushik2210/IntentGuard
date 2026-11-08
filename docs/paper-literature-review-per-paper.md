# Related Work, one paragraph per paper (draft)

Five closest papers, in order of citation. Built from the matrix, whose findings were written from abstracts: verify each claim
against the full paper before you keep it.

## II. Related Work

**A. Defeating Prompt Injections by Design (CaMeL).** Debenedetti et al. [1] argue that injection should be handled by system
design and not by asking the model to resist it. Their approach wraps the language model and extracts the control flow and data
flow from the trusted user query, so untrusted data cannot change what the program does. Capabilities attached to values block
exfiltration over flows that are not authorized. The authors report a utility cost compared with an undefended system, which is
the central trade-off of the design. CaMeL is the strongest example of flow-based protection and shows that a guarantee can be
obtained outside the model. IntentGuard differs in that it keeps the agent's own planning and instead authorizes each call
against the user's task, which is more flexible but gives a weaker, rule-based guarantee.

**B. Progent: Securing AI Agents with Privilege Control.** Shi et al. [2] apply the principle of least privilege to agents. They
express privilege as symbolic rules over tool names and arguments that are checked deterministically before a call runs. A
language model drafts and updates the policy for the task, and a solver classifies each update as narrowing, which is applied
automatically, or expanding, which needs approval, so confinement is monotonic unless a person agrees. The authors identify the
trade-off between security and utility, and the need for the policy to follow the task and the state of execution. Progent is a
preprint. It is the closest prior work to our rule-based gateway, and IntentGuard adds session-level risk and tracking of
sensitive content on top of per-call rules.

**C. Intent-Governed Tool Authorization for AI Agents.** Zhu and Wang [3] introduce intent-governed access control, a
server-side layer that narrows the static tool manifest to the current request and checks a tool's effects and payload before it
executes. It cannot grant authority beyond the static policy, so it can only restrict. The authors note that confinement depends
on the fidelity of the intent certificate and on sound bounds for tool effects. This 2026 preprint is the nearest published idea
to the "intent" in our title, so our paper must compare against it directly and explain what is different. As far as the matrix
shows, the difference is our cumulative risk, content-lineage tracking, human review and audit log, but this should be confirmed
from the full text.

**D. The Task Shield.** Jia et al. [4] defend against indirect injection by checking that each agent action aligns with the task
the user specified, treating instructions and tool calls that do not serve that task as suspect. This moves the question from
whether the text looks malicious to whether the action is justified. The abstract does not state the limitations clearly, so
read the full paper before describing them. The Task Shield shares our premise that the user's task is the right yardstick. Our
work differs by compiling the task into explicit scope rules and grants that are checked deterministically, and by combining that
check with data sensitivity, destination trust and session history.

**E. STAC: When Innocent Tools Form Dangerous Chains.** Li et al. [5] show that tool calls that are each harmless can be chained
into a harmful operation. Their attack, Sequential Tool Attack Chaining, reaches an average final attack success of 91.2%. They
find that prompt-based defences protect little, and that a defence designed for sequences, ToolShield, lasts longer. The
implication is that a defence must reason over the whole sequence of actions and not over isolated calls. This is the main
evidence for our decision to accumulate risk across a session and reduce permissions in stages. STAC appeared at a workshop, and
its venue was not found in Scopus, so cite it with that in mind.

## References

[1] E. Debenedetti et al., "Defeating prompt injections by design," in *Proc. IEEE Conf. Secure and Trustworthy Machine Learning (SaTML)*, 2025. doi: 10.48550/arXiv.2503.18813.
[2] T. Shi et al., "Progent: Securing AI agents with privilege control," arXiv preprint, 2025. doi: 10.48550/arXiv.2504.11703. [preprint]
[3] G. Zhu and C. Wang, "Intent-governed tool authorization for AI agents," arXiv preprint, 2026. doi: 10.48550/arXiv.2606.22916. [preprint]
[4] F. Jia, T. Wu, X. Qin, and A. Squicciarini, "The Task Shield: Enforcing task alignment to defend against indirect prompt injection in LLM agents," in *Proc. Annu. Meeting Assoc. Comput. Linguistics (ACL)*, 2024. doi: 10.48550/arXiv.2412.16682.
[5] J.-J. Li et al., "STAC: When innocent tools form dangerous chains for LLM agents," in *Proc. Workshop Research on Agent Language Models (REALM)*, 2026. doi: 10.18653/2026.realm-1.17.
