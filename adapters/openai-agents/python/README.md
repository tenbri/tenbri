# tenbri-openai-agents

[Tenbri](https://github.com/tenbri/tenbri) for the [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/):
every tool call, handoff and approval of an agent becomes a signed, chained decision that anyone
holding the stream's key fingerprint can verify offline.

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

Contents are pinned by keyed digest (`digest_key` at `AsyncTenbri.open`). Entries carry the SDK's
trace id, so a decision and its trace find each other.

Use one recorder per run, or per conversation when a run resumes after approvals. Pass
`run_config=recorder.run_config(your_config)`: it is how the recorder hears that a tool raised
(otherwise only the SDK's default error message tells). Use `async with` so a run that raises
closes its open intents; a process that dies mid-action leaves its intent open, and the next writer
session reconciles it as `unknown`.

[examples/refunds.py](examples/refunds.py) runs end to end, with or without an OpenAI API key.
