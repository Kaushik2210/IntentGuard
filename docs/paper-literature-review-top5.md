# Related Work, five-paper version (draft)

Five papers chosen as the closest to IntentGuard: CaMeL, Progent, intent-governed access control, The Task Shield and STAC.
Built from the matrix, whose findings columns were written from abstracts, so verify each claim against the full paper.

## II. Related Work

Defences against indirect prompt injection in tool-using agents are moving from changing the model to enforcing policy around it.
Five works are closest to ours, and they fall into three groups: designs that constrain what an agent may do, designs that tie
actions to the user's intent, and evidence that attacks built from several permitted steps escape both.

**Constraining what the agent can do.** CaMeL wraps the language model and extracts control flow and data flow from the trusted
user query, so that untrusted data cannot alter the program's flow, and capabilities block exfiltration over flows that are not
authorized [1]. Its authors report a utility cost compared with an undefended system. Progent takes a different route and
expresses privilege as symbolic rules over tool names and arguments that are checked deterministically [2]. A language model
drafts and updates the policy, and a solver classifies each update as narrowing, which is applied automatically, or expanding,
which needs approval, so confinement only tightens unless a person agrees. Both designs show that enforcement outside the model
can be deterministic and inspectable. Progent is a preprint.

**Tying actions to intent.** Intent-governed access control narrows a static tool manifest to the current request and checks the
effects of a tool call and its payload before it runs, and it cannot grant authority beyond the static policy [3]. Its confinement
depends on how faithful the intent certificate is and on sound bounds for tool effects, and it is also a preprint. The Task Shield
asks a related question at the action level, checking whether each agent action contributes to the task the user specified, and
rejecting those that do not [4]. These two are the nearest prior art to IntentGuard's use of the user's task as the basis for
authorization, and the comparison with them should be made directly.

**Attacks made of allowed steps.** STAC chains tool calls that are each harmless into a harmful operation, reports an average
final attack success of 91.2%, and finds that prompt-based defences protect little while a defence that reasons over the whole
action sequence lasts longer [5]. This matters for the designs above, because a rule that judges one call at a time, or a
task-alignment check applied per action, can pass every step of such a chain.

**Position of this work.** In the sources reviewed, enforcement is mostly judged call by call, against static or task-derived
policy. IntentGuard keeps a task-scoped decision for each call but adds three elements that are less developed in these five:
risk that accumulates across a session and narrows permissions in stages, tracking of sensitive content the session has already
read and matching it against outbound data after decoding, and a human-review path with a tamper-evident audit log. It is
evaluated on synthetic sets that share an author with the system, so we make no claim that it outperforms [1]-[4]; no
head-to-head comparison has been run.

## References

[1] E. Debenedetti et al., "Defeating prompt injections by design," in *Proc. IEEE Conf. Secure and Trustworthy Machine Learning (SaTML)*, 2025. doi: 10.48550/arXiv.2503.18813.
[2] T. Shi et al., "Progent: Securing AI agents with privilege control," arXiv preprint, 2025. doi: 10.48550/arXiv.2504.11703. [preprint]
[3] G. Zhu and C. Wang, "Intent-governed tool authorization for AI agents," arXiv preprint, 2026. doi: 10.48550/arXiv.2606.22916. [preprint]
[4] F. Jia et al., "The Task Shield: Enforcing task alignment to defend against indirect prompt injection in LLM agents," in *Proc. Annu. Meeting Assoc. Comput. Linguistics (ACL)*, 2024. doi: 10.48550/arXiv.2412.16682.
[5] J.-J. Li et al., "STAC: When innocent tools form dangerous chains for LLM agents," in *Proc. Workshop Research on Agent Language Models (REALM)*, 2026. doi: 10.18653/2026.realm-1.17.
