
# SkillSync (aka SkillGuard) — Project Context

## One-sentence summary
SkillSync is a **pre-install CLI security assistant** that gives developers an **explainable risk report** for AI skills / agent tools / plugin-like GitHub repos **before they are run**, similar to a “nutrition label” for code.

---

## Problem / Motivation

AI skills, agent tools, MCP tools, and plugin-like repos are going viral. Developers (especially “vibe coders”) are installing random GitHub repos based on trust, popularity, or vibes and running them locally.

These tools often have:
- shell execution access
- filesystem read/write access
- network access
- environment variable access (tokens, secrets)
- CI / GitHub Actions execution surfaces

There is **no pre-install warning layer** like browser extension permission screens.

Existing tools (Snyk, Dependabot, npm audit, VirusTotal) do **not** solve this problem well because:
- they focus on known CVEs, not behavior
- they assume a curated dependency ecosystem
- they operate after trust has already been granted
- they are not designed for loosely defined “skills” or agent tools

---

## Product Claim (IMPORTANT)

SkillSync **does NOT claim malware detection**.

SkillSync claims:
> “We surface explainable risk signals and evidence so developers can decide whether to run a skill.”

This is **decision support**, not antivirus.

---

## Core Mental Model

SkillSync’s output is split into three first-class concepts:

### 1. Capabilities (Neutral)
What the code *can do*:
- shell execution
- network egress
- filesystem read/write
- environment variable reads
- access to sensitive paths

Capabilities alone should **not** imply danger.

---

### 2. Red Flags (Weighted Heavily)
How the code does things in risky ways:
- `curl | bash`, `wget | sh`
- runtime download + execute
- obfuscated execution (base64 → exec, eval)
- persistence mechanisms (cron, systemd, launch agents, registry)
- `postinstall` / `preinstall` scripts
- unpinned GitHub Actions
- docker:// GitHub Actions
- suspicious shell commands in CI workflows

Red flags drive risk scoring.

---

### 3. Inspectability (Trust Gaps)
Things we cannot confidently inspect:
- opaque binaries (`.exe`, `.dll`, `.so`, `.dylib`, `.bin`)
- packed or minified code (huge single-line, low whitespace)
- lockfiles (transitive install scripts may exist)
- parse failures (YAML / JSON / TOML)

Inspectability increases risk **only when combined with red flags**.

---

## UX Form Factor

**CLI-first** (hackathon MVP).

Primary commands:
```bash
skillguard scan <repo_or_path> [--purpose <enum>] [--format pretty|json]
skillguard install <repo_or_path> --cmd "<install command>" [--yes]

Critical UX rules
	•	Scanning is static only (never executes code)
	•	Install wrapper is dry-run by default
	•	Exact install command is always printed
	•	Execution only happens with explicit --yes
	•	Clear disclaimer: “Static analysis only”

⸻

Purpose Flag (Expectedness Context)

--purpose is an enum with default unknown:

unknown | agent_skill | formatter | linter | build_tool | devops | cli | library

Purpose affects context labeling only (expected vs unexpected), not heavy scoring changes.

⸻

Scan Surfaces (MUST COVER)

SkillSync scans common execution surfaces, not just source code:

Language / Repo Files
	•	package.json scripts: preinstall, install, postinstall, prepare
	•	*.sh, *.ps1, *.bat
	•	Makefile, Justfile
	•	Dockerfile, docker-compose.yml
	•	.git/hooks/*
	•	pyproject.toml, setup.py, requirements.txt (best-effort)
	•	src/**/*.{js,ts,py} (basic text scan)

GitHub Actions (VERY IMPORTANT)
	•	.github/workflows/* is treated as an execution surface
	•	uses: owner/repo@ref = remote code execution by design
	•	warn if unpinned (tag/branch instead of SHA)
	•	uses: docker://... = remote execution risk
	•	uses: ./.github/actions/* = local action
	•	parse action.yml
	•	handle composite actions (runs: using: composite)
	•	scan all run: steps like shell scripts

Lockfiles
	•	package-lock.json, pnpm-lock.yaml, yarn.lock
	•	Emit inspectability finding:
“Dependencies may run install scripts; transitive behavior not fully inspected.”
	•	Optional: parse package-lock.json for install-script hints

⸻

Ignored Paths (Noise Control)

Always skip:

node_modules/
.git/
dist/
build/
vendor/
.venv/
__pycache__/


⸻

Parse Failure = Signal

If YAML / JSON / TOML fails to parse:
	•	Emit inspectability finding: PARSE_ERROR
	•	Severity: medium
	•	Confidence: low
	•	Never crash the scan

⸻

Unified Finding Model (KEY)

Everything emitted is a Finding:

Finding = {
  kind: "capability" | "red_flag" | "inspectability",
  code: string,                  // stable identifier
  title: string,
  severity: "low" | "medium" | "high",
  confidence: "low" | "medium" | "high",
  context?: "expected" | "unexpected" | "unknown",
  evidence: {
    file: string,                // repo-relative
    line?: number,
    excerpt?: string
  }[],
  details?: Record<string, any>
}

All scoring and “top reasons” are derived deterministically from Findings.

⸻

High-Signal MVP Rulepack

Red Flags
	•	CURL_PIPE_SH
	•	DOWNLOAD_EXEC
	•	POSTINSTALL_EXEC
	•	BASE64_EXEC
	•	EVAL_DYNAMIC
	•	PERSISTENCE
	•	GHA_USES_REMOTE
	•	GHA_USES_UNPINNED
	•	GHA_USES_DOCKER
	•	GHA_RUN_SHELL

Capabilities
	•	SHELL_EXEC
	•	NETWORK_EGRESS
	•	FS_WRITE
	•	ENV_READ
	•	SENSITIVE_PATH_READ

Inspectability
	•	OPAQUE_BINARY
	•	PACKED_OR_MINIFIED
	•	LOCKFILE_PRESENT
	•	PARSE_ERROR

⸻

Scoring Philosophy
	•	Capabilities = low weight
	•	Red flags = high weight
	•	Inspectability = medium weight
	•	High risk should be rare
	•	High usually requires:
	•	red flag + inspectability
	•	or multiple red flags across different surfaces

Top reasons ranked by:

severity_weight * confidence_weight
→ then code priority
→ then file path / line (for stability)


⸻

Output Structure

Console (Human-First)
	•	Header (repo, purpose, scan time)
	•	Risk label + score breakdown
	•	Top 5 reasons
	•	Capabilities summary
	•	Red flags
	•	Inspectability
	•	Disclaimer

JSON (Machine-Friendly)

{
  "summary": {...},
  "breakdown": {...},
  "top_reasons": [...],
  "findings": [...]
}


⸻

Demo Strategy (Hackathon)

Use 2–3 curated repos:
	1.	Safe repo → mostly capabilities, few/no red flags
	2.	Risky repo → unpinned GitHub Action + curl | bash + postinstall
	3.	Opaque repo → binary + lockfile + minified bundle

Demo flow:

skillguard scan safe-repo
skillguard scan risky-repo
skillguard install risky-repo --cmd "npm i"


⸻

Non-Goals (Do NOT Build)
	•	Malware detection
	•	Runtime sandboxing
	•	Full dependency resolution
	•	Enterprise dashboards
	•	Deep AST for multiple languages
	•	README intent inference

⸻

Tagline / Pitch Reminder

“SkillSync shows you what a skill can do before you run it.
Vibes aren’t a security model.”

---

If you want, next I can:
- tailor this **exactly** to SkillSync branding vs SkillGuard naming  
- shorten it into a **Cursor system prompt**  
- or generate a **repo skeleton** that matches this context 1:1