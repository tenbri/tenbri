// Dies inside a tool call: the intent must already be durable.
import { join } from 'node:path'
import { createAgent, tool } from 'langchain'
import { z } from 'zod'
import { Tenbri } from 'tenbri'
import { TenbriCallbackHandler } from '../dist/index.js'
import { model } from './fake.mts'

const dir = process.argv[2]
const log = await Tenbri.open(join(dir, 's'), { keys: join(dir, 'keys'), create: true })
const deploy = tool(() => process.exit(3), { name: 'deploy', description: 'Deploy.', schema: z.object({ env: z.string() }) })
const agent = createAgent({ model: model([[['deploy', { env: 'prod' }]]]), tools: [deploy] })
await agent.invoke({ messages: [{ role: 'user', content: 'go' }] }, { callbacks: [new TenbriCallbackHandler(log)] })
