import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const { version } = createRequire(import.meta.url)('../index.js')

test('the addon loads and reports its version', () => {
  assert.ok(version())
})
