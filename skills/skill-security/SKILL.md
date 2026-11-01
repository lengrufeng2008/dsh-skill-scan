---
name: skill-security
description: First-pass static security review of a skill or plugin bundle before installation. Use skill_scan for instruction override, remote shell, credential access, lifecycle scripts, JS patches, and encoded payloads. The result is evidence, not a safety certificate.
whenToUse: "Before installing a third-party skill/plugin, before publishing a bundle, or when a security review needs a fast static first pass."
---

# Skill security

## What the scanner checks

- **Instruction override / exfiltration** language in skills and text files
- **Remote shell**: download piped into `sh`/`bash`
- **Destructive root/home delete**
- **Credential paths** such as `.ssh/id_rsa` or `.aws/credentials`
- **Dynamic code** (`eval`, `new Function`)
- **Long encoded payloads**
- **Hidden Unicode** (bidi/zero-width controls)
- **Package lifecycle scripts**
- **`!!js` in Cordis patches**

## Use

```text
Use skill_scan on /path/to/bundle.
```

Read the findings, then inspect the exact file and line. A high finding is a **block until explained**, not
a conviction. A clean scan is a **PASS for these heuristics only**.

## Limits

- Static only; no sandbox detonation.
- No AST taint analysis, no dependency/OSV lookup, no signature database.
- False positives happen: a security document may quote an attack, and a legitimate installer may use a
  lifecycle script. Context matters.
- It does not check runtime permissions, network destinations, model behavior, or the honesty of the
  author.
- Do not install a bundle just because the score is high.

## Before installing

1. Read `SKILL.md` and the patch itself.
2. Check the package's lifecycle scripts and dependencies.
3. Run the scanner; explain every high finding.
4. Use a disposable profile/container for a first run.
5. Keep credentials out of the agent's working directory.
