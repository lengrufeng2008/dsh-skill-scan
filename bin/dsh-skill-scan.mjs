#!/usr/bin/env node
import { scanPath, renderMarkdown } from '../src/scan.mjs'
const args = process.argv.slice(2)
if (args.includes('--help') || args.includes('-h')) {
  console.log('dsh-skill-scan <dir> [--json]\n\nStatic, read-only skill/plugin security first pass. Exit 1 on BLOCK.')
  process.exit(0)
}
const json = args.includes('--json')
const target = args.find((a) => !a.startsWith('--')) || '.'
try {
  const report = await scanPath(target)
  if (json) console.log(JSON.stringify(report, null, 2))
  else console.log(renderMarkdown(report))
  process.exitCode = report.verdict === 'BLOCK' ? 1 : 0
} catch (error) {
  console.error(`dsh-skill-scan: ${error.message}`)
  process.exitCode = 2
}
