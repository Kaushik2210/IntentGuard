"""LangChain / LangGraph tools that route every call through an IntentGuard session.

    session = open_http_session("http://localhost:8000", task, grants)       # or InProcessSession(...)
    agent = create_agent(model, guarded_tools(session))                      # langchain.agents

The tools hold no real capability. When IntentGuard does not allow a call, the tool returns the explanation
as text, so the model can tell the user what happened instead of looping.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from ..client import Session


class ReadFile(BaseModel):
    path: str = Field(description="Path of the file to read")


class SearchFiles(BaseModel):
    query: str = Field(description="Text to search for in file names and contents")


class SendEmail(BaseModel):
    to: str = Field(description="Recipient email address")
    body: str = Field(description="Message body")
    attachment: str | None = Field(default=None, description="Optional path of a file to attach")


class Upload(BaseModel):
    url: str = Field(description="Destination URL")
    data: str = Field(description="Data to upload")


class RunShell(BaseModel):
    cmd: str = Field(description="Shell command to run")


class DbQuery(BaseModel):
    sql: str = Field(description="SQL statement")


# name -> (description, schema). Names match the tools the gateway knows.
SPECS: dict[str, tuple[str, type[BaseModel]]] = {
    "read_file": ("Read a file by path", ReadFile),
    "search_files": ("Search files for text", SearchFiles),
    "send_email": ("Send an email", SendEmail),
    "upload": ("Upload data to a URL", Upload),
    "run_shell": ("Run a shell command", RunShell),
    "db_query": ("Run a database query", DbQuery),
}


def _make(session: Session, name: str, description: str, schema: type[BaseModel]) -> StructuredTool:
    def run(**kwargs: Any) -> str:
        args = {k: v for k, v in kwargs.items() if v is not None}
        res = session.call(name, **args)
        return str(res.output) if res.allowed and not res.error else res.message()

    return StructuredTool.from_function(func=run, name=name, description=description, args_schema=schema)


def guarded_tools(session: Session, only: list[str] | None = None) -> list[StructuredTool]:
    """One LangChain tool per gateway tool (or the subset named in `only`)."""
    return [_make(session, n, d, s) for n, (d, s) in SPECS.items() if only is None or n in only]
