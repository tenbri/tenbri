// A chat model that plays back one AI message per turn, tool calls included, then a final answer.
import { BaseChatModel } from '@langchain/core/language_models/chat_models'
import { AIMessage, type BaseMessage } from '@langchain/core/messages'
import type { ChatResult } from '@langchain/core/outputs'

type Call = [name: string, args: Record<string, unknown>]

class Scripted extends BaseChatModel {
  #turns: AIMessage[]
  constructor(turns: AIMessage[]) {
    super({})
    this.#turns = turns
  }
  _llmType() {
    return 'scripted'
  }
  bindTools() {
    return this as any
  }
  async _generate(_messages: BaseMessage[]): Promise<ChatResult> {
    const message = this.#turns.shift() ?? new AIMessage('done')
    return { generations: [{ message, text: String(message.content) }] }
  }
}

/** One AI message per turn, each with its tool calls (ids `call_<turn>_<i>`), then "done". */
export function model(turns: Call[][]): BaseChatModel {
  return new Scripted(
    turns.map(
      (calls, t) =>
        new AIMessage({ content: '', tool_calls: calls.map(([name, args], i) => ({ name, args, id: `call_${t}_${i}`, type: 'tool_call' })) }),
    ),
  )
}
