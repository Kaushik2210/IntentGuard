# MCP gateway: end-to-end demo with the dashboard

What this shows: an MCP client asks a tool to email an unapproved recipient, the call waits, a human approves it in
the dashboard, and the client gets the real result. A second call to the same recipient does not wait again, and an
email to a denylisted address is blocked outright.

## Run it

1. Start the dashboard (reads its backend from `http://localhost:8000`):
   ```bash
   cd dashboard && npm install && npm run dev        # http://localhost:3000
   ```
2. Start any MCP client against the gateway with the approval API on port 8000. With the official Python SDK
   (`pip install mcp`), the client spawns the gateway itself:
   ```python
   params = StdioServerParameters(command="python", args=[
       "-m", "intentguard.mcp_gateway", "--demo",
       "--task", "Summarize research/notes.md and email bob@newlab.org",
       "--grants", '{"resources":["research/*"],"project_root":"research/","max_classification":"INTERNAL","destinations":["advisor@university.edu"]}',
       "--approvals-port", "8000", "--approval-timeout", "240"])
   ```
   then `call_tool("send_email", {"to": "bob@newlab.org", "body": "..."})`.
3. Open `http://localhost:3000/approvals`. The call is listed with the rule that flagged it (EGRESS-001, destination
   not on the approved list). Click **Approve** (or **Reject**).

## What was observed (one manual run)

| Step | Result |
|---|---|
| `read_file research/notes.md` | allowed immediately |
| `send_email bob@newlab.org` | waited about 28 s for the click, then returned `sent` |
| `send_email bob@newlab.org` again | allowed in 0.00 s (approval remembered for the session) |
| `send_email attacker@evil.example` | blocked: destination denylisted |

The gateway process hosts the approval API, so the dashboard can only see approvals while the MCP client's gateway
is running. When the client exits, the API goes away and the dashboard shows "Cannot reach IntentGuard API".
