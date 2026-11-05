"""A tiny stdio MCP server used as the upstream in proxy tests. Logs every tools/call it actually receives."""

import json
import os
import sys

TOOLS = [
    {"name": "read_note", "description": "Read a note", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "send_message", "description": "Send a message", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}, "required": ["to", "body"]}},
    {"name": "delete_all", "description": "Delete everything", "inputSchema": {"type": "object", "properties": {}}},
]


def log(entry):
    with open(os.environ["FAKE_MCP_LOG"], "a") as f:
        f.write(json.dumps(entry) + "\n")


for line in sys.stdin:
    msg = json.loads(line)
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        continue
    if method == "initialize":
        res = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "0"}}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg["params"]
        log({"tool": p["name"], "args": p.get("arguments")})
        res = {"content": [{"type": "text", "text": f"{p['name']} ok: {p.get('arguments')}"}], "isError": False}
    else:
        res = {}
    print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}), flush=True)
