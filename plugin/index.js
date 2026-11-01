// DSH host plugin: read-only static scan for skill/plugin bundles.
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scanPath, renderMarkdown } from '../src/scan.mjs'

const PLUGIN_DIR = dirname(fileURLToPath(import.meta.url))
const SKILL_PATH = join(PLUGIN_DIR, '..', 'skills', 'skill-security', 'SKILL.md')
const PROVIDER = 'dsh-skill-scan'
export const name = 'skill-scan'
export const inject = ['tools', 'skills']

function stripFrontmatter(text) {
  if (!text.startsWith('---\n')) return text
  const end = text.indexOf('\n---\n', 4)
  return end === -1 ? text : text.slice(end + 5)
}
const summary = {
  name: 'skill-security',
  description: 'Static, read-only scan of a skill or plugin bundle for instruction override, remote shell, credential access, lifecycle scripts, JS patches, and obfuscation. A PASS is not proof of safety.',
  whenToUse: 'Before installing or publishing a skill/plugin bundle, or when a bundle needs a first-pass security review.',
  invocation: { modelInvocable: true, userInvocable: true },
  source: 'bundled', provider: PROVIDER,
  resourceBase: { kind: 'directory', path: join(PLUGIN_DIR, '..', 'skills', 'skill-security') },
  rank: 600, locator: 'skill-security', metadata: { domain: 'security', version: '0.1.0' },
}

export function apply(ctx) {
  ctx.tools.register({
    name: 'skill_scan',
    description: 'Static, read-only security scan of a local skill/plugin bundle. Finds instruction override, remote shell, credential access, lifecycle scripts, JS patches, and encoded payloads. Does not execute the bundle and is not a full security audit.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        path: { type: 'string', description: 'Bundle directory to scan.' },
        format: { type: 'string', enum: ['markdown', 'json'], description: 'Output format. Default markdown.' },
      },
      required: ['path'],
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { markdown: { type: 'string' }, count: { type: 'integer' }, verdict: { type: 'string' }, score: { type: 'integer' } },
        required: ['markdown', 'count', 'verdict', 'score'],
      },
      render: (_args, value) => [{ type: 'text', text: value.markdown }],
    },
    timeoutMs: 30_000,
    async execute(args = {}) {
      const report = await scanPath(args.path)
      return {
        markdown: args.format === 'json' ? JSON.stringify(report, null, 2) : renderMarkdown(report),
        count: report.findings.length,
        verdict: report.verdict,
        score: report.score,
      }
    },
  })
  ctx.skills.registerProvider(() => ({
    name: PROVIDER,
    async list() { return [summary] },
    async get(candidate) {
      if (candidate?.name !== 'skill-security') return undefined
      return { ...summary, content: stripFrontmatter(await readFile(SKILL_PATH, 'utf8')) }
    },
  }))
}
