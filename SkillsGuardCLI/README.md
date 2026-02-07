# SkillsGuard

**Pre-install security scanner for AI skills, agent tools, and plugin repos.**

> "Vibes aren't a security model."

SkillsGuard gives developers an explainable risk report for AI skills, agent tools, and plugin-like GitHub repos **before they are run** — like a nutrition label for code.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan a local directory
skillguard scan /path/to/repo

# Scan a GitHub repo
skillguard scan github.com/owner/repo

# Scan with purpose context
skillguard scan ./my-skill --purpose agent_skill

# JSON output
skillguard scan ./my-skill --format json

# Install wrapper (dry-run by default)
skillguard install ./my-skill --cmd "npm install"

# Install with auto-confirm
skillguard install ./my-skill --cmd "npm install" --yes
```

## What It Detects

### Red Flags (High Weight)
- `CURL_PIPE_SH` — curl | bash, wget | sh
- `DOWNLOAD_EXEC` — runtime download + execute
- `POSTINSTALL_EXEC` — npm postinstall/preinstall scripts
- `BASE64_EXEC` — obfuscated execution (base64 + eval)
- `EVAL_DYNAMIC` — eval() with dynamic input
- `PERSISTENCE` — cron, systemd, launchd, registry writes
- `GHA_USES_REMOTE` — remote GitHub Action usage
- `GHA_USES_UNPINNED` — unpinned GitHub Actions (tag/branch vs SHA)
- `GHA_USES_DOCKER` — docker:// GitHub Actions
- `GHA_RUN_SHELL` — suspicious shell commands in CI

### Capabilities (Neutral)
- `SHELL_EXEC` — shell/subprocess execution
- `NETWORK_EGRESS` — network requests
- `FS_WRITE` — filesystem writes
- `ENV_READ` — environment variable access
- `SENSITIVE_PATH_READ` — access to sensitive paths

### Inspectability (Trust Gaps)
- `OPAQUE_BINARY` — binary files that can't be inspected
- `PACKED_OR_MINIFIED` — minified/packed code
- `LOCKFILE_PRESENT` — lockfiles with potential hidden install scripts
- `PARSE_ERROR` — files that fail to parse

## Disclaimer

SkillsGuard performs **static analysis only** — code is never executed. This is decision support, not malware detection.
