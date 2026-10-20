# tenbri-openai-agents

[Tenbri](https://github.com/tenbri/tenbri) for the [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/):
every tool call, handoff and approval of an agent becomes a signed, chained decision that anyone
holding the stream's key fingerprint can verify offline.

```sh
pip install --pre tenbri-openai-agents
```

```python
import tenbri

tenbri.init()  # TENBRI_STREAM=./audit/support TENBRI_APPROVER=person:alice
tenbri.instrument_openai_agents()
```

From then on every `Runner.run`, `run_sync` and `run_streamed` is recorded, by `agent:<the
agent's name>`, and so is every `RunState.approve` and `reject`, with no `hooks=` to pass.
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
tenbri.instrument_openai_agents(
    actions={"issue_refund": {"target": "stripe:{charge}", "policy": "policy:refund@14"}}
)
```

## Approvals

Answer interruptions the SDK's way; both answers are recorded before the run resumes:

```python
result = await Runner.run(agent, "Refund 80 EUR on ch_2")
state = result.to_state()
for item in result.interruptions:
    state.approve(item)  # an approval entry by TENBRI_APPROVER, which the tool's intent names
result = await Runner.run(agent, state)
```

`state.reject(item)` records the call's intent and a `refused` outcome by the approver. The approver
is `TENBRI_APPROVER`, `init(approver=...)`, or `instrument_openai_agents(approver=...)`: a principal,
or a function of the `ToolApprovalItem`.

## Advanced: `TenbriRecorder`

The one-liner is built on `TenbriRecorder`, the run hooks of one run on a stream you opened. What it records,
below, is what the one-liner records.

```python
from agents import Runner
from tenbri import AsyncTenbri
from tenbri_openai_agents import TenbriRecorder

log = await AsyncTenbri.open("s3://acme-audit/tenbri/support")
async with TenbriRecorder(log) as recorder:
    result = await Runner.run(agent, "Refund ch_123", hooks=recorder, run_config=recorder.run_config())
```

| What happens | What is recorded |
| --- | --- |
| A tool call | An intent by `agent:<name>`, action the tool's name, durable before the tool runs; then the outcome `ok`, or `error` if the tool raised |
| A tool input guardrail rejects or trips, or a person rejects the call | An intent and the outcome `refused` (by the person, for a rejection) |
| A handoff | An intent and an outcome `ok`, action `handoff`, target `agent:<next agent>` |
| `await recorder.approve(state, item, "person:alice")` | An `approval` entry; the tool's intent names it in `approval` |
| The run raises | The open intents end in `error` (`unknown` when cancelled) |

The SDK awaits its run hooks, so the guarantee is **enforce**: if the intent cannot be written, the
run stops before the tool runs. `fail_open=True` lets the tool run instead and logs a warning.

Tool arguments, results and prompts are never written. Choose what is:

```python
TenbriRecorder(
    log,
    tools=["issue_refund", "close_ticket"],                 # default: every tool
    target=lambda tool, args: f"stripe:{args['charge']}",   # action.target
    inputs=lambda tool, args: [{"ref": "policy:refund", "version": "14", "content": policy}],
    subject=customer_handle,                                # per-subject keys, for erasure
)
recorder.read("ticket:4821", "3", ticket_text)              # pinned to the next decision
```

Contents are pinned by keyed digest, keyed by the stream's local key store. Entries carry the SDK's
trace id, so a decision and its trace find each other.

Use one recorder per run, or per conversation when a run resumes after approvals. Pass
`run_config=recorder.run_config(your_config)`: it is how the recorder hears that a tool raised
(otherwise only the SDK's default error message tells). Use `async with` so a run that raises
closes its open intents; a process that dies mid-action leaves its intent open, and the next writer
session reconciles it as `unknown`.

[examples/refunds.py](examples/refunds.py) runs end to end, with or without an OpenAI API key.
