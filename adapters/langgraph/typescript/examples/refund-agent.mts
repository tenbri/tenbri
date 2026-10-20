// A support agent that refunds charges, recorded in Tenbri: one refund under the policy limit, one
// a person reviews and approves first. Runs offline with a scripted model; swap in a real one
// (`initChatModel('anthropic:claude-sonnet-5-5')`) and nothing else changes.
//
//   npm install --save tenbri@next @tenbri/langgraph@next langchain @langchain/core @langchain/langgraph zod
//   node refund-agent.mts
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { BaseChatModel } from '@langchain/core/language_models/chat_models'
import { AIMessage } from '@langchain/core/messages'
import type { ChatResult } from '@langchain/core/outputs'
import { MemorySaver } from '@langchain/langgraph'
import { createAgent, humanInTheLoopMiddleware, tool } from 'langchain'
import { z } from 'zod'
import { Refused, Tenbri } from 'tenbri'
import { TenbriCallbackHandler } from '@tenbri/langgraph'

const issueRefund = tool(
  async ({ charge, amount }: { charge: string; amount: number }) => {
    if (amount > 500) throw new Refused('over the refund ceiling')
    return `refunded ${amount} EUR of ${charge}`
  },
  { name: 'issue_refund', description: 'Refund `amount` EUR of a charge.', schema: z.object({ charge: z.string(), amount: z.number() }) },
)

// Plays back the turns a model would take.
class Scripted extends BaseChatModel {
  turns = [call('c1', 'ch_1', 20), new AIMessage('Refunded.'), call('c2', 'ch_2', 120), new AIMessage('Refunded.')]
  _llmType() {
    return 'scripted'
  }
  bindTools() {
    return this as any
  }
  async _generate(): Promise<ChatResult> {
    const message = this.turns.shift()!
    return { generations: [{ message, text: '' }] }
  }
}
function call(id: string, charge: string, amount: number) {
  return new AIMessage({ content: '', tool_calls: [{ id, name: 'issue_refund', args: { charge, amount }, type: 'tool_call' }] })
}

const dir = mkdtempSync(join(tmpdir(), 'tenbri-example-'))
const log = await Tenbri.open(join(dir, 'support'), { keys: join(dir, 'keys'), create: true, digestKey: 'a 32-byte secret, kept apart....' })
const tenbri = new TenbriCallbackHandler(log, {
  target: (_tool, args) => `stripe:${args.charge}`,
  inputs: () => [{ ref: 'policy:refund', version: '14', content: 'refunds over 50 EUR need a person' }],
})
const agent = createAgent({
  model: new Scripted({}),
  tools: [issueRefund],
  name: 'support',
  // Refunds over 50 EUR wait for a person.
  middleware: [
    humanInTheLoopMiddleware({
      interruptOn: { issue_refund: { allowedDecisions: ['approve', 'reject'], when: (r: any) => r.toolCall.args.amount > 50 } },
    }),
  ],
  checkpointer: new MemorySaver(),
})
const config = { callbacks: [tenbri], configurable: { thread_id: 'ticket-42' } }

await agent.invoke({ messages: [{ role: 'user', content: 'Refund 20 EUR of ch_1' }] }, config)
await agent.invoke({ messages: [{ role: 'user', content: 'Refund 120 EUR of ch_2' }] }, config)
const state: any = await agent.getState(config)
console.log('waiting for a person:', JSON.stringify(state.tasks.flatMap((t: any) => t.interrupts).map((i: any) => i.value.actionRequests)))
await agent.invoke(await tenbri.resume(agent, config, { decisions: [{ type: 'approve' }] }, { by: 'person:alice' }), config)

await log.flush()
for (const { entry: e } of await log.query()) {
  if (e.kind !== 'decision' && e.kind !== 'approval') continue
  const who = `${e.principal!.kind}:${e.principal!.id}`
  console.log(String(e.seq).padStart(2), e.kind.padEnd(8), (e.phase ?? '').padEnd(7), (e.status ?? '').padEnd(7), who.padEnd(14), e.action!.target)
}
const report = await log.verify(log.fingerprint!)
console.log('verified:', report.ok, `(${report.entries} entries)`)
await log.close()
