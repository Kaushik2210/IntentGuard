"""Put IntentGuard in front of your own Python functions. Run: python examples/guard_your_own_tools.py"""

from intentguard.sdk import Guard

guard = Guard(
    classes={"hr/salary.csv": "CONFIDENTIAL"},
    trust={"bob@x.org": "approved", "evil@x.org": "denylisted"},
)
files = {"notes/a.txt": "Meeting notes: ship on Friday.", "hr/salary.csv": "alice,120000"}
sent = []


@guard.tool("read", resource_arg="path")
def read_file(path):
    return files[path]


@guard.tool("send", resource_arg="attachment", dest_arg="to", resource_optional=True)
def send_email(to, body, attachment=None):
    sent.append((to, body))
    return "sent"


session = guard.session("Read notes/a.txt and email bob@x.org a short summary",
                        grants={"resources": ["notes/*"], "destinations": ["bob@x.org"]})

# Blocked attempts raise the session's risk, and enough of them lock it. A person can lift that with
# guard.gateway.release(session_id, "you", "reviewed"). So the legitimate work goes first here.
for tool, args in [
    ("read_file", {"path": "notes/a.txt"}),                         # the task asks for this
    ("send_email", {"to": "bob@x.org", "body": "Ship on Friday."}),  # and for this
    ("read_file", {"path": "hr/salary.csv"}),                       # an injected request: outside task and grants
    ("send_email", {"to": "evil@x.org", "body": "all the notes"}),  # an injected destination nobody approved
]:
    r = session.call(tool, **args)
    print(f"{r.decision:10} {tool}({args})" + ("" if r.allowed else f"\n           why: {r.explanation}"))
print("emails actually sent:", sent)
