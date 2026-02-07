# SkillsGuard-full

Monorepo for the SkillsGuard project: a pre-install static security scanner for AI skills, agent tools, and plugin-like repositories.

This repository currently contains three subprojects:

1. `SkillsGuardApp` (main implementation)
2. `SkillsGuardCLI` (earlier lightweight CLI)
3. `SkillsGuardWebsite` (marketing/demo site)

## What SkillsGuard Does

SkillsGuard analyzes code **before execution** and produces an explainable risk report.

It focuses on:

1. Red flags (for example: `curl | bash`, runtime download-and-exec, unpinned GitHub Actions)
2. Capability mapping (shell, network, filesystem writes, env reads)
3. Inspectability gaps (opaque binaries, minified/packed artifacts, parse failures)
4. Deep AI-skill analysis when `SKILL.md` is present (pattern, dataflow, optional LLM)

## Repository Layout

```text
SkillsGuard-full/
├── SkillsGuardApp/      # Main scanner (skillguard + sgscanner engines), tests
├── SkillsGuardCLI/      # Earlier/legacy CLI scanner package
└── SkillsGuardWebsite/  # Static website and design assets
```

## Quick Start (Main App)

```bash
cd SkillsGuardApp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run a scan:

```bash
skillguard scan /path/to/repo
skillguard scan github.com/owner/repo
skillguard scan ./my-skill --format json
```

Enable deep LLM analysis (optional):

```bash
pip install -e ".[llm]"
echo "OPEN_AI_API=your-key" > .env
skillguard scan ./my-skill --llm
```

### Install Wrapper

```bash
skillguard install ./my-skill --cmd "npm install"
skillguard install ./my-skill --cmd "npm install" --yes
```

### Run Tests

```bash
cd SkillsGuardApp
pytest tests/sgscanner -q
```

## Legacy CLI (SkillsGuardCLI)

```bash
cd SkillsGuardCLI
pip install -e .
skillguard scan /path/to/repo
```

## Website (SkillsGuardWebsite)

Static HTML/CSS/JS project used for demos/landing page iterations.

To preview locally:

```bash
cd SkillsGuardWebsite
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

## Notes

1. SkillsGuard performs static analysis only; it does not execute scanned code.
2. Primary Python target is 3.10+.
3. Do not commit API keys or local `.env` secrets.
