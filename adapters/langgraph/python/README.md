# tenbri-langgraph

[Tenbri](https://github.com/tenbri/tenbri) for LangGraph and LangChain: every tool call your agent
makes is a signed, chained decision.

```sh
pip install --pre tenbri-langgraph
```

```python
import tenbri

tenbri.init()  # TENBRI_STREAM=./audit/support TENBRI_APPROVER=person:alice
tenbri.instrument_langchain()
```

From then on every tool call of every LangChain agent and LangGraph graph in the process is
recorded, in every thread, with no `callbacks` to pass. The principal is the agent's name
(`create_agent(name=...)`), else `TENBRI_AGENT`.
`tenbri.init()` creates the stream and its keys on first use and flushes at exit; see the
[tenbri package](../../../bindings/python) for its settings and `@tenbri.decision` for your own
functions.

## Which action, which target, which policy

A tool call is the action of the tool's name. Declare the action in `tenbri.toml` (the action
schemas tenbrid and `tenbri schema check` validate against) and the record takes its target and
rule from there, filled from the tool's arguments:

```toml
[actions.issue_refund]
target = "stripe:{charge}"      # each {argument} is filled from the call; validated as *
policy = "policy:refund@14"     # the rule that allowed it: ref@version
```

`init()` reads `./tenbri.toml` (or `TENBRI_SCHEMA`). A tool matches an action by its name or its
last `__` part, so the MCP tool `mcp__billing__issue_refund` is `issue_refund`. A plain dict in
code says the same, and wins:

```python
tenbri.instrument_langchain(
    actions={"issue_refund": {"target": "stripe:{charge}", "policy": "policy:refund@14"}}
)
```

## Human in the loop

With `HumanInTheLoopMiddleware` (and a checkpointer), resume the graph the LangGraph way; the
answers in the `Command` are recorded as it starts:

```python
config = {"configurable": {"thread_id": "t1"}}
agent.invoke({"messages": [("user", "refund ch_123")]}, config)  # paused for review
agent.invoke(Command(resume={"decisions": [{"type": "approve"}]}), config)
```

`approve` and `edit` write an `approval` entry by `TENBRI_APPROVER` (or `init(approver=...)`, or
`instrument_langchain(approver=...)`: a principal, or a function of the tool and its arguments),
and the tool's intent names it. `reject` writes the call's intent and a `refused` outcome.

## Advanced: `TenbriCallbackHandler`

The one-liner is built on `TenbriCallbackHandler`, a handler on a stream you opened, passed in
`callbacks`, with `resume()` recording the answers for a person you name. What it records,
below, is what the one-liner records.

```python
from langchain.agents import create_agent
from tenbri import Tenbri
from tenbri_langgraph import TenbriCallbackHandler

log = Tenbri.open("./audit/support", create=True)
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
- **Inputs**: the call's arguments are pinned as a keyed digest
  (`langchain:tool_call/<id>@args`); `inputs(tool, args)` pins more, such as a policy version.
  Arguments and results are never stored.
- **Selection**: `tools=["issue_refund"]` or a predicate records only those tools.
- **Traces**: the active OpenTelemetry span goes into `trace` (install `tenbri-langgraph[otel]`);
  the LangChain run id, the tool call id and the LangGraph thread id go into `ext.langchain`, so a
  LangSmith run and a decision find each other.
- **Fail closed** by default: when the stream can't be written, the tool call fails.
  `fail_open=True` runs the tool anyway and logs a warning.

### Human in the loop

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
