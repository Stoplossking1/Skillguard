"""
CLI entry point for SkillsGuard.

Commands:
  skillguard scan <repo_or_path> [--purpose <enum>] [--format pretty|json]
  skillguard install <repo_or_path> --cmd "<command>" [--yes]
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from . import __version__
from .models import Purpose
from .reporter import format_json, format_pretty
from .scanner import scan


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

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    """Handle the scan command."""
    purpose = Purpose(args.purpose)

    try:
        result = scan(args.target, purpose=purpose)
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

    try:
        result = scan(args.target, purpose=purpose)
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
        # Dry-run mode: ask for confirmation
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
