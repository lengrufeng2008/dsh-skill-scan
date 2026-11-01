import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scanPath } from '../src/scan.mjs'
import { apply } from '../plugin/index.js'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))

test('a safe fixture passes the static heuristics', async () => {
  const report = await scanPath(join(ROOT, 'test/fixtures/safe'))
  assert.deepEqual(report.findings, [])
  assert.equal(report.verdict, 'PASS')
  assert.equal(report.score, 100)
})

test('the unsafe fixture is blocked with named rules', async () => {
  const report = await scanPath(join(ROOT, 'test/fixtures/unsafe'))
  assert.equal(report.verdict, 'BLOCK')
  const rules = new Set(report.findings.map((f) => f.rule))
  for (const rule of ['prompt-injection', 'remote-shell', 'credential-path', 'lifecycle-script', 'js-patch']) assert.ok(rules.has(rule), rule)
  assert.ok(report.score < 50)
})

test('the CLI exits non-zero for BLOCK and zero for PASS', () => {
  const block = spawnSync(process.execPath, [join(ROOT, 'bin/dsh-skill-scan.mjs'), join(ROOT, 'test/fixtures/unsafe')], { encoding: 'utf8' })
  assert.equal(block.status, 1)
  assert.match(block.stdout, /BLOCK/)
  const safe = spawnSync(process.execPath, [join(ROOT, 'bin/dsh-skill-scan.mjs'), join(ROOT, 'test/fixtures/safe')], { encoding: 'utf8' })
  assert.equal(safe.status, 0)
  assert.match(safe.stdout, /PASS/)
})

test('the plugin registers the tool and skill', async () => {
  const tools = []
  let factory
  apply({ tools: { register: (tool) => tools.push(tool) }, skills: { registerProvider: (fn) => { factory = fn } } })
  assert.equal(tools[0].name, 'skill_scan')
  const result = await tools[0].execute({ path: join(ROOT, 'test/fixtures/unsafe') })
  assert.equal(result.verdict, 'BLOCK')
  assert.ok(result.count >= 4)
  const provider = factory()
  assert.equal((await provider.list())[0].name, 'skill-security')
  const skill = await provider.get({ name: 'skill-security' })
  assert.match(skill.content, /skill_scan/)
  assert.equal(await provider.get({ name: 'missing' }), undefined)
})
