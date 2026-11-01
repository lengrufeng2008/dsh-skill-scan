# Skill Scan for DSH

> A static first pass for third-party skills and plugin bundles. Inspired by NVIDIA SkillSpector's
> supply-chain idea, implemented as a small DSH tool plus a CLI. It does not execute the bundle.

## What it finds

- Instruction override / exfiltration language
- `curl ... | sh` remote shell
- destructive root/home delete
- credential paths (`.ssh/id_rsa`, `.aws/credentials`)
- `eval` / `new Function`
- long encoded payloads
- hidden Unicode (bidi/zero-width)
- package lifecycle scripts
- `!!js` in Cordis patches

## CLI

```bash
node bin/dsh-skill-scan.mjs /path/to/bundle
node bin/dsh-skill-scan.mjs /path/to/bundle --json
```

Exit `1` on a `BLOCK`, `0` on `PASS`/`WARN`, `2` on invalid input.

## DSH plugin

```bash
dsh plugin --profile web add /home/lrf/dsh/products/dsh-skill-scan
```

Then ask: “Use skill_scan on this bundle.” The tool is read-only.

## What a result means

`PASS` means **no finding under these heuristics**. It is not proof of safety. `BLOCK` means a high
finding needs an explanation before installation. Read the exact file and line; the scanner is not a
sandbox, AST taint engine, OSV lookup, or runtime monitor.

False positives are possible: a security document may quote an attack, and a legitimate package may
use a lifecycle script. Context matters.

## Tests

```bash
npm test
```

The fixtures include a deliberately unsafe bundle; the test only reads it as text and never executes it.

## Provenance

Inspired by [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector); no source code copied.
See `NOTICE.md`. License: MIT.
