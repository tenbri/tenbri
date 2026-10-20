# tenbri-langgraph

[Tenbri](https://github.com/tenbri/tenbri) for LangGraph and LangChain: every tool call your agent
makes is a signed, chained decision. One callback handler at agent setup.

```sh
pip install --pre tenbri-langgraph
```

```python
from langchain.agents import create_agent
from tenbri import Tenbri
from tenbri_langgraph import TenbriCallbackHandler

log = Tenbri.open("./audit/support", create=True, digest_key=b"a 32-byte secret, kept apart....")
tenbri = TenbriCallbackHandler(log, target=lambda tool, args: args.get("charge"))

agent = create_agent(model, tools=[issue_refund], name="support")
agent.invoke({"messages": [("user", "refund ch_123")]}, {"callbacks": [tenbri]})
print(log.verify(log.fingerprint).ok)
```

- **Before each tool call** its intent is durable in the stream, or the tool does not run (the
  handler has `raise_error=True`). After it comes the outcome: `ok`, `error`, or `refused` when
  the tool raises `tenbri.Refused`. LangGraph's `ToolNode` re-raises a tool's exception unless
  `handle_tool_errors` is set, so a refusal, or an intent that could not be written, ends the
  run with that exception. A process that dies mid-call leaves the intent open, and the stream's
  next writer reconciles it as `unknown`.
- **Who and what**: `principal` is the agent (`create_agent(name=...)`, or `principal=`), `action`
  is the tool, `target` is what `target(tool, args)` returns.
- **Inputs**: with a `digest_key`, the call's arguments are pinned as a keyed digest
  (`langchain:tool_call/<id>@args`); `inputs(tool, args)` pins more, such as a policy version.
  Arguments and results are never stored.
- **Selection**: `tools=["issue_refund"]` or a predicate records only those tools.
- **Traces**: the active OpenTelemetry span goes into `trace` (install `tenbri-langgraph[otel]`);
  the LangChain run id, the tool call id and the LangGraph thread id go into `ext.langchain`, so a
  LangSmith run and a decision find each other.
- **Fail closed** by default: when the stream can't be written, the tool call fails.
  `fail_open=True` runs the tool anyway and logs a warning.

## Human in the loop

With LangChain's `HumanInTheLoopMiddleware` (and a checkpointer), record the person's answer
as you resume the graph:

```python
config = {"callbacks": [tenbri], "configurable": {"thread_id": "t1"}}
agent.invoke({"messages": [("user", "refund ch_123")]}, config)  # paused for review
agent.invoke(tenbri.resume(agent, config, {"decisions": [{"type": "approve"}]}, by="person:alice"), config)
```

`approve` and `edit` write an `approval` entry, and the tool's intent names it
(`approval: {by, entry}`), so the stream answers "who approved this, and on what basis".
`reject` writes the call's intent and a `refused` outcome. For an `interrupt()` of your own, call
`tenbri.approve(tool, args, by=..., tool_call_id=...)` once the person has answered.

A runnable example is in [examples/refund_agent.py](examples/refund_agent.py).
