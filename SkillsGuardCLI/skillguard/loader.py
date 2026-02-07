"""
File loader for SkillsGuard.

Accepts a GitHub URL or local path, walks the directory tree,
skips ignored directories, and returns a categorized file map.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Directories completely skipped (never walked)
FULLY_IGNORED_DIRS = frozenset({
    "node_modules",
    ".git",
    ".venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "egg-info",
})

# Directories where we only look for inspectability signals
# (binaries, minified files) but skip pattern scanning
INSPECTABILITY_ONLY_DIRS = frozenset({
    "dist",
    "build",
    "vendor",
})

SHELL_EXTENSIONS = frozenset({".sh", ".bash", ".ps1", ".bat", ".cmd"})
SOURCE_EXTENSIONS = frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py"})
BINARY_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin", ".node",
    ".wasm", ".o", ".a", ".lib",
})
LOCKFILE_NAMES = frozenset({
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
})
DOCKERFILE_NAMES = frozenset({
    "Dockerfile", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
})
BUILD_FILE_NAMES = frozenset({
    "Makefile", "makefile", "Justfile", "justfile",
})
PACKAGE_MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "setup.py", "setup.cfg",
})

GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?github\.com/([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)(?:\.git)?/?$"
)


# ---------------------------------------------------------------------------
# File map
# ---------------------------------------------------------------------------

@dataclass
class FileMap:
    """Categorized files found in a repo."""
    root: Path
    shell_scripts: list[Path] = field(default_factory=list)
    package_manifests: list[Path] = field(default_factory=list)
    ci_workflows: list[Path] = field(default_factory=list)
    dockerfiles: list[Path] = field(default_factory=list)
    build_files: list[Path] = field(default_factory=list)
    lockfiles: list[Path] = field(default_factory=list)
    source_code: list[Path] = field(default_factory=list)
    binaries: list[Path] = field(default_factory=list)
    other: list[Path] = field(default_factory=list)

    @property
    def all_files(self) -> list[Path]:
        return (
            self.shell_scripts
            + self.package_manifests
            + self.ci_workflows
            + self.dockerfiles
            + self.build_files
            + self.lockfiles
            + self.source_code
            + self.binaries
            + self.other
        )

    @property
    def total_count(self) -> int:
        return len(self.all_files)

    def rel(self, path: Path) -> str:
        """Return repo-relative path string."""
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def resolve_target(target: str) -> tuple[Path, bool]:
    """
    Resolve the scan target to a local directory path.

    Returns (path, is_temp) where is_temp=True if we cloned to a tempdir.
    """
    # Check if it looks like a GitHub URL
    match = GITHUB_URL_RE.match(target)
    if match:
        repo_slug = match.group(1)
        clone_url = f"https://github.com/{repo_slug}.git"
        tmp_dir = tempfile.mkdtemp(prefix="skillguard_")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", clone_url, tmp_dir],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to clone {clone_url}: {e.stderr.strip()}") from e
        except subprocess.TimeoutExpired:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RuntimeError(f"Clone timed out for {clone_url}")
        return Path(tmp_dir), True

    # Local path
    local = Path(target).resolve()
    if not local.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")
    if not local.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {target}")
    return local, False


def _should_fully_skip(name: str) -> bool:
    """Check if a directory should be completely skipped."""
    lower = name.lower()
    if lower in FULLY_IGNORED_DIRS:
        return True
    if lower.endswith(".egg-info"):
        return True
    return False


def _is_inspectability_only(name: str) -> bool:
    """Check if a directory should only be scanned for inspectability."""
    return name.lower() in INSPECTABILITY_ONLY_DIRS


def _categorize(path: Path, name: str) -> str:
    """Return the category key for a file."""
    suffix = path.suffix.lower()

    # CI workflows
    parts = path.parts
    if ".github" in parts:
        idx = parts.index(".github")
        if len(parts) > idx + 1 and parts[idx + 1] == "workflows":
            if suffix in (".yml", ".yaml"):
                return "ci_workflows"

    # Git hooks
    if ".git" in parts:
        idx = parts.index(".git")
        if len(parts) > idx + 1 and parts[idx + 1] == "hooks":
            return "shell_scripts"

    # By exact filename
    if name in LOCKFILE_NAMES:
        return "lockfiles"
    if name in DOCKERFILE_NAMES:
        return "dockerfiles"
    if name in BUILD_FILE_NAMES:
        return "build_files"
    if name in PACKAGE_MANIFEST_NAMES:
        return "package_manifests"

    # By extension
    if suffix in SHELL_EXTENSIONS:
        return "shell_scripts"
    if suffix in SOURCE_EXTENSIONS:
        return "source_code"
    if suffix in BINARY_EXTENSIONS:
        return "binaries"

    return "other"


def walk_directory(root: Path) -> FileMap:
    """
    Walk a directory tree and categorize all files.

    - Fully ignored dirs (node_modules, .git, etc.) are never entered.
    - Inspectability-only dirs (dist, build, vendor) are walked but files
      are only categorized as binaries or source (for minified detection).
    """
    file_map = FileMap(root=root)

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out fully ignored directories
        dirnames[:] = [d for d in dirnames if not _should_fully_skip(d)]

        # Check if current dir is inside an inspectability-only path
        rel_parts = Path(dirpath).relative_to(root).parts
        in_inspectability_dir = any(_is_inspectability_only(p) for p in rel_parts)

        for fname in filenames:
            fpath = Path(dirpath) / fname
            suffix = fpath.suffix.lower()

            if in_inspectability_dir:
                # Only pick up binaries and source (for minified detection)
                if suffix in BINARY_EXTENSIONS:
                    file_map.binaries.append(fpath)
                elif suffix in SOURCE_EXTENSIONS:
                    file_map.source_code.append(fpath)
                # Skip everything else in these dirs
            else:
                category = _categorize(fpath, fname)
                getattr(file_map, category).append(fpath)

    return file_map


def load_target(target: str) -> tuple[FileMap, bool]:
    """
    Load and categorize all files from a scan target.

    Returns (file_map, is_temp).
    Caller is responsible for cleanup if is_temp=True.
    """
    root, is_temp = resolve_target(target)
    file_map = walk_directory(root)
    return file_map, is_temp


def cleanup_temp(root: Path) -> None:
    """Remove a temporary clone directory."""
    shutil.rmtree(root, ignore_errors=True)


def extract_repo_name(target: str) -> str:
    """Extract a short repo name from a target path or URL."""
    match = GITHUB_URL_RE.match(target)
    if match:
        return match.group(1)
    # Local path: use the directory name
    return Path(target).resolve().name
