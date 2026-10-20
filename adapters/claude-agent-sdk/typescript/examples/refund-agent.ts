// A support agent that can issue refunds, every tool call recorded in a Tenbri stream.
//
//   npm install @tenbri/claude-agent-sdk @anthropic-ai/claude-agent-sdk tenbri@next zod
//   export ANTHROPIC_API_KEY=...
//   npm run example
//
// The refund tool asks you first (canUseTool); your answer is recorded as an approval by
// person:$USER. Then the stream is verified and its decisions listed.
import { userInfo } from 'node:os'
import { createInterface } from 'node:readline/promises'
import { createSdkMcpServer, query, tool, type CanUseTool, type SDKUserMessage } from '@anthropic-ai/claude-agent-sdk'
import { init } from 'tenbri'
import { z } from 'zod'
import { instrumentClaudeAgentSdk } from '../src/index.js' // '@tenbri/claude-agent-sdk' outside this repository

const log = await init({ stream: './audit/support', agent: 'agent:support', approver: `person:${userInfo().username}` })
const actions = { issue_refund: { target: 'stripe:{charge}', policy: 'policy:refund@14' } }

const billing = createSdkMcpServer({
  name: 'billing',
  tools: [
    tool('issue_refund', 'Refund a Stripe charge', { charge: z.string(), amount_eur: z.number().int() }, async (a) => ({
      content: [{ type: 'text', text: `refunded ${a.amount_eur} EUR` }],
    })),
  ],
})

const ask: CanUseTool = async (name, input) => {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const answer = await rl.question(`Allow ${name} ${JSON.stringify(input)}? [y/N] `)
  rl.close()
  return answer.toLowerCase() === 'y' ? { behavior: 'allow', updatedInput: input } : { behavior: 'deny', message: 'no' }
}

async function* prompt(): AsyncGenerator<SDKUserMessage> {
  const content = 'Ticket 4512: the customer was charged twice (ch_123, 30 EUR). Refund the duplicate.'
  yield { type: 'user', message: { role: 'user', content }, parent_tool_use_id: null, session_id: '' }
}

const options = instrumentClaudeAgentSdk(
  {
    mcpServers: { billing },
    tools: [], // no built-in tools: only the refund, which asks first
    canUseTool: ask,
  },
  { actions },
)
for await (const message of query({ prompt: prompt(), options })) console.log(message.type)

console.log('verified:', (await log.verify(log.fingerprint ?? undefined)).ok)
for (const { entry: e } of await log.query({ action: 'issue_refund' })) {
  console.log(e.seq, e.phase, e.status ?? '', e.action, e.approval ?? '')
}
