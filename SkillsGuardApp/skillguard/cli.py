"""
CLI entry point for SkillsGuard.

Commands:
  skillguard scan <repo_or_path> [--purpose <enum>] [--format pretty|json]
                                 [--deep|--no-deep] [--llm] [--dataflow]
  skillguard install <repo_or_path> --cmd "<command>" [--yes]
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from . import __version__
from .models import Purpose
from .reporter import format_json, format_pretty
from .scanner import DeepScanOptions, scan


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description="SkillsGuard — Pre-install security scanner for AI skills, agent tools, and plugin repos.",
        epilog="Vibes aren't a security model.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"skillguard {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- scan ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a repo or directory for security risks",
        description="Scan a GitHub repo URL or local directory and produce an explainable risk report.",
    )
    scan_parser.add_argument(
        "target",
        help="GitHub URL (github.com/owner/repo) or local path to scan",
    )
    scan_parser.add_argument(
        "--purpose",
        choices=[p.value for p in Purpose],
        default=Purpose.UNKNOWN.value,
        help="Purpose of the repo (affects context labels). Default: unknown",
    )
    scan_parser.add_argument(
        "--format",
        choices=["pretty", "json"],
        default="pretty",
        dest="output_format",
        help="Output format. Default: pretty",
    )

    # Deep analysis flags
    deep_group = scan_parser.add_mutually_exclusive_group()
    deep_group.add_argument(
        "--deep",
        action="store_true",
        default=False,
        help="Force deep skill analysis even if no SKILL.md is found",
    )
    deep_group.add_argument(
        "--no-deep",
        action="store_true",
        default=False,
        help="Skip deep skill analysis entirely",
    )
    scan_parser.add_argument(
        "--llm",
        action="store_true",
        default=False,
        help="Enable LLM semantic analysis engine (requires OPEN_AI_API in .env)",
    )
    scan_parser.add_argument(
        "--dataflow",
        action="store_true",
        default=True,
        help="Enable dataflow/taint analysis engine (default: on)",
    )
    scan_parser.add_argument(
        "--no-dataflow",
        action="store_true",
        default=False,
        help="Disable dataflow/taint analysis engine",
    )

    # --- install ---
    install_parser = subparsers.add_parser(
        "install",
        help="Scan then install (dry-run by default)",
        description="Run a security scan, show the report, then optionally execute an install command.",
    )
    install_parser.add_argument(
        "target",
        help="GitHub URL (github.com/owner/repo) or local path",
    )
    install_parser.add_argument(
        "--cmd",
        required=True,
        help='Install command to run (e.g. "npm install")',
    )
    install_parser.add_argument(
        "--purpose",
        choices=[p.value for p in Purpose],
        default=Purpose.UNKNOWN.value,
        help="Purpose of the repo (affects context labels). Default: unknown",
    )
    install_parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation and execute the install command",
    )
    install_parser.add_argument(
        "--llm",
        action="store_true",
        default=False,
        help="Enable LLM semantic analysis engine (requires OPEN_AI_API in .env)",
    )

    return parser


def _build_deep_options(args: argparse.Namespace) -> DeepScanOptions:
    """Build DeepScanOptions from parsed CLI arguments."""
    if getattr(args, "no_deep", False):
        return DeepScanOptions(enabled=False)

    enabled = True if getattr(args, "deep", False) else None  # None = auto-detect
    use_dataflow = not getattr(args, "no_dataflow", False)
    use_llm = getattr(args, "llm", False)

    return DeepScanOptions(
        enabled=enabled,
        use_pattern=True,
        use_dataflow=use_dataflow,
        use_llm=use_llm,
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    """Handle the scan command."""
    purpose = Purpose(args.purpose)
    deep_opts = _build_deep_options(args)

    try:
        result = scan(args.target, purpose=purpose, deep=deep_opts)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except NotADirectoryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.output_format == "json":
        print(format_json(result))
    else:
        print(format_pretty(result))

    return 0


def _cmd_install(args: argparse.Namespace) -> int:
    """Handle the install command."""
    purpose = Purpose(args.purpose)
    deep_opts = DeepScanOptions(
        enabled=None,
        use_llm=getattr(args, "llm", False),
    )

    try:
        result = scan(args.target, purpose=purpose, deep=deep_opts)
    except (FileNotFoundError, NotADirectoryError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Always show the report first
    print(format_pretty(result))

    # Show install intent
    print(f"  {'─' * 51}")
    print(f"  Install command: {args.cmd}")
    print(f"  Target:          {args.target}")
    print(f"  {'─' * 51}")
    print()

    if not args.yes:
        try:
            answer = input("  Proceed with installation? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
            return 0

        if answer not in ("y", "yes"):
            print("  Cancelled.")
            return 0

    # Execute the install command
    print(f"\n  Running: {args.cmd}\n")
    try:
        exit_code = subprocess.call(args.cmd, shell=True)
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        return 130

    if exit_code == 0:
        print("\n  Install completed successfully.")
    else:
        print(f"\n  Install exited with code {exit_code}.", file=sys.stderr)

    return exit_code


def main() -> int:
    """Main CLI entry point."""
    # Load .env early so keys are available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "install":
        return _cmd_install(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
