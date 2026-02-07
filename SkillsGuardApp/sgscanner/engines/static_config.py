# Copyright 2026 SkillsGuard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Configuration for the pattern detector.

Centralizes thresholds, regex patterns, and allowlists that were previously
hard-coded in the analyzer implementation.
"""

from dataclasses import dataclass, field
import re
from typing import Pattern

from ..models import Severity


@dataclass(frozen=True)
class AssetPattern:
    """Asset scanning rule definition."""

    pattern: Pattern[str]
    rule_id: str
    severity: Severity
    description: str


@dataclass(frozen=True)
class PatternEngineConfig:
    """Configuration for PatternEngine behavior and patterns."""

    # Manifest validation
    manifest_name_pattern: Pattern[str] = field(default_factory=lambda: re.compile(r"[a-z0-9-]+"))
    manifest_name_max_length: int = 64
    manifest_description_max_length: int = 1024
    manifest_description_min_length: int = 20
    anthropic_legitimate_keywords: tuple[str, ...] = (
        "apply",
        "brand",
        "guidelines",
        "colors",
        "typography",
        "style",
    )
    anthropic_official_markers: tuple[str, ...] = ("claude official",)

    # Reference scanning
    reference_scan_max_depth: int = 5
    reference_search_dirs: tuple[str, ...] = ("references", "assets", "templates", "scripts")

    # File patterns
    markdown_link_pattern: Pattern[str] = field(default_factory=lambda: re.compile(r"\[([^\]]+)\]\(([^\)]+)\)"))
    python_import_pattern: Pattern[str] = field(
        default_factory=lambda: re.compile(r"^from\s+\.([A-Za-z0-9_.]*)\s+import", re.MULTILINE)
    )
    bash_source_pattern: Pattern[str] = field(
        default_factory=lambda: re.compile(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))")
    )
    rm_target_pattern: Pattern[str] = field(default_factory=lambda: re.compile(r"rm\s+-r[^;]*?\s+([^\s;]+)"))

    # Code usage detection patterns
    read_patterns: tuple[Pattern[str], ...] = field(
        default_factory=lambda: (
            re.compile(r"open\([^)]+['\"]r['\"]"),
            re.compile(r"open\([^)]+\)"),
            re.compile(r"\.read\("),
            re.compile(r"\.readline\("),
            re.compile(r"\.readlines\("),
            re.compile(r"Path\([^)]+\)\.read_text"),
            re.compile(r"Path\([^)]+\)\.read_bytes"),
            re.compile(r"with\s+open\([^)]+['\"]r"),
        )
    )
    write_patterns: tuple[Pattern[str], ...] = field(
        default_factory=lambda: (
            re.compile(r"open\([^)]+['\"]w['\"]"),
            re.compile(r"\.write\("),
            re.compile(r"\.writelines\("),
            re.compile(r"pathlib\.Path\([^)]+\)\.write"),
            re.compile(r"with\s+open\([^)]+['\"]w"),
        )
    )
    grep_patterns: tuple[Pattern[str], ...] = field(
        default_factory=lambda: (
            re.compile(r"re\.search\("),
            re.compile(r"re\.findall\("),
            re.compile(r"re\.match\("),
            re.compile(r"re\.finditer\("),
            re.compile(r"re\.sub\("),
            re.compile(r"\.search\("),
            re.compile(r"\.findall\("),
            re.compile(r"grep"),
        )
    )
    glob_patterns: tuple[Pattern[str], ...] = field(
        default_factory=lambda: (
            re.compile(r"glob\.glob\("),
            re.compile(r"glob\.iglob\("),
            re.compile(r"Path\([^)]*\)\.glob\("),
            re.compile(r"\.glob\("),
            re.compile(r"\.rglob\("),
            re.compile(r"fnmatch\."),
        )
    )
    exception_patterns: tuple[Pattern[str], ...] = field(
        default_factory=lambda: (
            re.compile(r"except\s+(EOFError|StopIteration|KeyboardInterrupt|Exception|BaseException)"),
            re.compile(r"except\s*:"),
            re.compile(r"break\s*$", re.MULTILINE),
            re.compile(r"return\s*$", re.MULTILINE),
            re.compile(r"sys\.exit\s*\("),
            re.compile(r"raise\s+StopIteration"),
        )
    )

    # Allowed-tools and behavior heuristics
    bash_indicators: tuple[str, ...] = (
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "commands.getoutput",
        "shell=True",
    )
    external_network_indicators: tuple[str, ...] = (
        "import requests",
        "from requests import",
        "import urllib.request",
        "from urllib.request import",
        "import http.client",
        "import httpx",
        "import aiohttp",
    )


# Backwards-compatible alias
StaticAnalyzerConfig = PatternEngineConfig
    socket_external_indicators: tuple[str, ...] = ("socket.connect", "socket.create_connection")
    socket_localhost_indicators: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
    network_indicators: tuple[str, ...] = (
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "urllib.request",
        "urllib.urlopen",
        "http.client",
        "httpx.",
        "aiohttp.",
        "socket.connect",
        "socket.create_connection",
    )
    description_mismatch_keywords: tuple[str, ...] = ("calculator", "format", "template", "style", "lint")

    # Asset scanning
    asset_dirs: tuple[str, ...] = ("assets", "templates", "references", "data")
    asset_template_extensions: tuple[str, ...] = (".template", ".tmpl", ".tpl")
    asset_text_extensions: tuple[str, ...] = (".txt", ".json", ".yaml", ".yml")
    asset_patterns: tuple[AssetPattern, ...] = field(
        default_factory=lambda: (
            AssetPattern(
                re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                RiskLevel.HIGH,
                "Prompt injection pattern in asset file",
            ),
            AssetPattern(
                re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                RiskLevel.HIGH,
                "Prompt override pattern in asset file",
            ),
            AssetPattern(
                re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                RiskLevel.MEDIUM,
                "Role reassignment pattern in asset file",
            ),
            AssetPattern(
                re.compile(r"https?://[^\s]+\.(tk|ml|ga|cf|gq)/", re.IGNORECASE),
                "ASSET_SUSPICIOUS_URL",
                RiskLevel.MEDIUM,
                "Suspicious free domain URL in asset",
            ),
        )
    )

    # Binary file detection
    binary_asset_extensions: tuple[str, ...] = (
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".bmp",
        ".tiff",
        ".tar.gz",
        ".tgz",
        ".zip",
    )

    # YARA post-filtering allowlists
    yara_safe_commands: frozenset[str] = frozenset(
        {
            "soffice",
            "pandoc",
            "wkhtmltopdf",
            "convert",
            "gs",
            "pdftotext",
            "pdfinfo",
            "pdftoppm",
            "pdftohtml",
            "tesseract",
            "ffmpeg",
            "ffprobe",
            "zip",
            "unzip",
            "tar",
            "gzip",
            "gunzip",
            "bzip2",
            "bunzip2",
            "xz",
            "unxz",
            "7z",
            "7za",
            "gtimeout",
            "timeout",
            "grep",
            "head",
            "tail",
            "sort",
            "uniq",
            "wc",
            "file",
            "git",
        }
    )
    yara_safe_cleanup_dirs: frozenset[str] = frozenset(
        {
            "dist",
            "build",
            "tmp",
            "temp",
            ".tmp",
            ".temp",
            "bundle.html",
            "bundle.js",
            "bundle.css",
            "node_modules",
            ".next",
            ".nuxt",
            ".cache",
        }
    )
    yara_placeholder_markers: frozenset[str] = frozenset(
        {
            "your-",
            "your_",
            "your ",
            "example",
            "sample",
            "dummy",
            "placeholder",
            "replace",
            "changeme",
            "change_me",
            "<your",
            "<insert",
        }
    )
    unicode_i18n_markers: tuple[str, ...] = ("i18n", "locale", "translation", "lang=", "charset", "utf-8", "encoding")
    yara_skipped_rules: frozenset[str] = frozenset({"capability_inflation_generic"})
