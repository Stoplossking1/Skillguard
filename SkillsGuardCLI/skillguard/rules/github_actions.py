"""
GitHub Actions workflow parser.

Parses .github/workflows/*.yml files to extract:
  - uses: directives (remote actions, docker, local)
  - run: step contents (shell commands)
  - Pinning format (SHA vs tag vs branch)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ActionRef:
    """A parsed `uses:` directive from a workflow."""
    raw: str                # e.g. "actions/checkout@main"
    owner_repo: str | None  # e.g. "actions/checkout" or None for docker/local
    ref: str | None         # e.g. "main", "v4", or a SHA
    is_docker: bool = False
    is_local: bool = False
    is_pinned: bool = False  # True if ref looks like a full SHA
    job_name: str = ""
    step_name: str = ""
    line_number: int | None = None


@dataclass
class RunStep:
    """A parsed `run:` step from a workflow."""
    content: str
    job_name: str = ""
    step_name: str = ""
    line_number: int | None = None


# SHA pattern: 40 hex chars
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def _is_sha_pinned(ref: str) -> bool:
    """Check if a ref looks like a full commit SHA."""
    return bool(_SHA_RE.match(ref))


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_workflow(filepath: Path) -> tuple[list[ActionRef], list[RunStep]]:
    """
    Parse a GitHub Actions workflow YAML file.

    Returns (action_refs, run_steps).
    """
    action_refs: list[ActionRef] = []
    run_steps: list[RunStep] = []

    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return action_refs, run_steps

    # Track line numbers for uses: and run: directives
    uses_lines: dict[str, int] = {}
    run_lines: dict[int, int] = {}
    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("uses:"):
            value = stripped[5:].strip().strip('"').strip("'")
            uses_lines[value] = line_num
        if stripped.startswith("run:"):
            run_lines[line_num] = line_num

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return action_refs, run_steps

    if not isinstance(data, dict):
        return action_refs, run_steps

    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return action_refs, run_steps

    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue
        steps = job_def.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            step_name = step.get("name", "")

            # Parse uses:
            uses_val = step.get("uses")
            if uses_val and isinstance(uses_val, str):
                ref = _parse_uses(uses_val, job_name, step_name)
                # Try to find the line number
                ref.line_number = uses_lines.get(uses_val)
                action_refs.append(ref)

            # Parse run:
            run_val = step.get("run")
            if run_val and isinstance(run_val, str):
                run_step = RunStep(
                    content=run_val,
                    job_name=job_name,
                    step_name=step_name,
                )
                run_steps.append(run_step)

    return action_refs, run_steps


def _parse_uses(raw: str, job_name: str, step_name: str) -> ActionRef:
    """Parse a single uses: value into an ActionRef."""
    # Docker action
    if raw.startswith("docker://"):
        return ActionRef(
            raw=raw,
            owner_repo=None,
            ref=None,
            is_docker=True,
            job_name=job_name,
            step_name=step_name,
        )

    # Local action
    if raw.startswith("./") or raw.startswith("../"):
        return ActionRef(
            raw=raw,
            owner_repo=None,
            ref=None,
            is_local=True,
            job_name=job_name,
            step_name=step_name,
        )

    # Remote action: owner/repo@ref or owner/repo/path@ref
    if "@" in raw:
        parts = raw.split("@", 1)
        action_path = parts[0]
        ref = parts[1]
        # Extract owner/repo (first two segments)
        segments = action_path.split("/")
        owner_repo = "/".join(segments[:2]) if len(segments) >= 2 else action_path
        return ActionRef(
            raw=raw,
            owner_repo=owner_repo,
            ref=ref,
            is_pinned=_is_sha_pinned(ref),
            job_name=job_name,
            step_name=step_name,
        )

    # Fallback: just the action path, no ref
    return ActionRef(
        raw=raw,
        owner_repo=raw,
        ref=None,
        job_name=job_name,
        step_name=step_name,
    )
