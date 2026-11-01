import { readFile, readdir, stat } from 'node:fs/promises'
import { basename, extname, join, relative, resolve, sep } from 'node:path'

const RULES = [
  { id: 'prompt-injection', severity: 'high', pattern: /(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+instructions|you\s+are\s+now\s+(?:dan|developer|root)|exfiltrat|send\s+(?:the\s+)?(?:secret|token|key)/i, message: 'Instruction-override or exfiltration language in a skill/text file.' },
  { id: 'remote-shell', severity: 'high', pattern: /(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i, message: 'Remote download piped into a shell.' },
  { id: 'destructive-root', severity: 'high', pattern: /\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f|-[A-Za-z]*f[A-Za-z]*r)\s+(?:--\s+)?(?:\/(?:\s|$)|~(?:\/|\s|$)|\$(?:HOME|USERPROFILE)\b)/i, message: 'Recursive force delete of root/home.' },
  { id: 'credential-path', severity: 'high', pattern: /\.ssh[\\/](?:id_rsa|id_ed25519|authorized_keys)|\.aws[\\/]credentials|GITHUB_TOKEN|DEEPSEEK_API_KEY/i, message: 'Credential path or secret environment variable referenced by the plugin.' },
  { id: 'dynamic-code', severity: 'medium', pattern: /\beval\s*\(|new\s+Function\s*\(/i, message: 'Dynamic code execution primitive.' },
  { id: 'base64-payload', severity: 'medium', pattern: /['"`][A-Za-z0-9+/]{240,}={0,2}['"`]/, message: 'Long encoded payload; possible obfuscation.' },
  { id: 'hidden-unicode', severity: 'medium', pattern: /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]/, message: 'Bidirectional or zero-width control character in text.' },
  { id: 'js-patch', severity: 'medium', pattern: /!!js\b/, when: (file) => file.endsWith('cordis.patch.yml'), message: 'JS evaluation in a Cordis patch; review the expression.' },
]
const LIFECYCLE = /"(?:preinstall|install|postinstall|prepare)"\s*:/i
const SKIP = new Set(['.git', 'node_modules', 'dist'])
const TEXT = new Set(['.md', '.json', '.yml', '.yaml', '.mjs', '.js', '.cjs', '.ts', '.sh', '.bash', '.txt', '.html', '.css'])

async function walk(root) {
  const out = []
  async function visit(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (SKIP.has(entry.name)) continue
      const p = join(dir, entry.name)
      if (entry.isDirectory()) await visit(p)
      else out.push(p)
    }
  }
  await visit(root)
  return out
}

function lineOf(text, index) { return text.slice(0, index).split('\n').length }

export async function scanPath(input) {
  const root = await resolve(input)
  const info = await stat(root).catch(() => null)
  if (!info?.isDirectory()) throw new Error(`not a directory: ${input}`)
  const files = await walk(root)
  const findings = []
  const checked = []
  for (const file of files) {
    if (findings.length >= 200) break
    const ext = extname(file).toLowerCase()
    if (!TEXT.has(ext) && basename(file) !== 'package.json') continue
    const size = (await stat(file)).size
    if (size > 512 * 1024) continue
    const text = await readFile(file, 'utf8').catch(() => '')
    const rel = relative(root, file).split(sep).join('/')
    checked.push(rel)
    for (const rule of RULES) {
      if (rule.when && !rule.when(rel)) continue
      const match = rule.pattern.exec(text)
      if (!match) continue
      findings.push({ rule: rule.id, severity: rule.severity, file: rel, line: lineOf(text, match.index), message: rule.message })
    }
    if (basename(file) === 'package.json' && LIFECYCLE.test(text)) {
      findings.push({ rule: 'lifecycle-script', severity: 'medium', file: rel, line: 1, message: 'Package lifecycle script (preinstall/install/postinstall/prepare) present; review it.' })
    }
  }
  const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + (f.severity === 'high' ? 30 : 10), 0))
  return { root, files: files.length, checked, findings, score, verdict: findings.some((f) => f.severity === 'high') ? 'BLOCK' : findings.length ? 'WARN' : 'PASS' }
}

export function renderMarkdown(report) {
  const lines = [`# Skill scan: ${report.verdict}`, '', `Files: ${report.files}; checked: ${report.checked.length}; score: ${report.score}/100`, '']
  if (!report.findings.length) lines.push('No static findings. This is not a security audit.')
  else {
    lines.push('| Severity | Rule | File | Line | Message |', '| --- | --- | --- | --- | --- |')
    for (const f of report.findings) lines.push(`| ${f.severity} | ${f.rule} | ${f.file} | ${f.line} | ${f.message.replaceAll('|', '\\|')} |`)
  }
  lines.push('', 'Static heuristics only. A PASS is not proof of safety; read the skill and test in a sandbox.')
  return lines.join('\n')
}
