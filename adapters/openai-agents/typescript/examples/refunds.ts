// A support agent whose refunds are recorded in a Tenbri stream, approvals included.
//
//   npm install @tenbri/openai-agents @openai/agents
//   node examples/refunds.ts ./audit
//
// With OPENAI_API_KEY set it asks the model; without, a scripted model plays the same turns, so the
// example runs anywhere. Then `tenbri verify ./audit --key <fingerprint>` checks the record.
import { Agent, Usage, run, setTraceProcessors, tool, type AgentOutputItem, type Model } from '@openai/agents-core'
import { init } from 'tenbri'
import { instrumentOpenAIAgents } from '../src/index.ts' // '@tenbri/openai-agents' outside this repository

const log = await init({ stream: process.argv[2] ?? './audit', approver: 'person:alice' }) // a person answers the approvals
instrumentOpenAIAgents({ actions: { issue_refund: { target: 'stripe:{charge}', policy: 'policy:refund@14' } } })

const POLICY = 'Refunds up to 50 EUR are automatic; above that a person approves.'

const issueRefund = tool({
  name: 'issue_refund',
  description: 'Refunds `amount` EUR on the card charge `charge`.',
  parameters: {
    type: 'object',
    properties: { charge: { type: 'string' }, amount: { type: 'number' } },
    required: ['charge', 'amount'],
    additionalProperties: false,
  },
  strict: true,
  needsApproval: async (_context, args) => (args as { amount: number }).amount > 50,
  execute: async (args) => {
    const { charge, amount } = args as { charge: string; amount: number }
    return `refunded ${amount} EUR on ${charge}`
  },
})

/** Stands in for the model when there is no API key: two refunds, then a reply. */
function scripted(): Model {
  const refund = (callId: string, args: object): AgentOutputItem => ({
    type: 'function_call',
    name: 'issue_refund',
    callId,
    arguments: JSON.stringify(args),
    status: 'completed',
  })
  const turns: AgentOutputItem[][] = [
    [refund('c1', { charge: 'ch_1', amount: 20 }), refund('c2', { charge: 'ch_2', amount: 80 })],
    [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Both refunds are done.' }] }],
  ]
  return {
    async getResponse() {
      return { output: turns.shift() ?? [], usage: new Usage(), responseId: undefined }
    },
    getStreamedResponse() {
      throw new Error('not scripted')
    },
  }
}

if (process.env.OPENAI_API_KEY) await import('@openai/agents' as string) // the OpenAI model provider
else setTraceProcessors([]) // nowhere to export traces to; entries still carry their ids
const agent = new Agent({
  name: 'support-assistant',
  instructions: `You handle refunds. Policy: ${POLICY}`,
  tools: [issueRefund],
  ...(process.env.OPENAI_API_KEY ? {} : { model: scripted() }),
})

let result = await run(agent, 'Refund 20 EUR on ch_1 and 80 EUR on ch_2.')
while (result.interruptions.length) {
  for (const item of result.interruptions) result.state.approve(item) // recorded as an approval by person:alice
  result = await run(agent, result.state)
}

for (const { entry: e } of await log.query()) {
  console.log(e.seq, e.kind, e.phase ?? '', e.status ?? '', `${e.principal?.kind}:${e.principal?.id}`, e.action)
}
const report = await log.verify(log.fingerprint!)
console.log(report.ok ? 'verified' : `broken: ${JSON.stringify(report.broken)}`, '- key', log.fingerprint)
