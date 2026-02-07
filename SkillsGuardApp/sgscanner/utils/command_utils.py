import os
import shlex
import shutil
from typing import Any
try:
    from expandvars import expand as _expand_custom
    from expandvars import expandvars as _expandvars_lib
    _HAS_EXPANDVARS = True
except Exception:
    _expandvars_lib = _expand_custom = None
    _HAS_EXPANDVARS = False

def build_env_for_expansion(server_env: dict[str, Any] | None) -> dict[str, str]:
    merged = {**os.environ, **(server_env or {})}
    return {k: str(v) for k, v in merged.items()}

def decide_windows_semantics(expand_mode: str) -> bool:
    mode = (expand_mode or 'auto').lower()
    if mode == 'windows':
        return True
    if mode in ('linux', 'mac'):
        return False
    if mode == 'off':
        return os.name == 'nt'
    return os.name == 'nt'

def expand_text(text: str, env: dict[str, str], expand_mode: str) -> str:
    if not text:
        return ''
    text = os.path.expanduser(text)
    mode = (expand_mode or 'auto').lower()
    if mode == 'off':
        return text.strip()
    if mode == 'auto':
        mode = 'windows' if os.name == 'nt' else 'linux'
    try:
        if mode in ('linux', 'mac'):
            if _HAS_EXPANDVARS and _expandvars_lib:
                old_environ = dict(os.environ)
                try:
                    os.environ.update(env)
                    return _expandvars_lib(text).strip()
                finally:
                    os.environ.clear()
                    os.environ.update(old_environ)
            return os.path.expandvars(text).strip()
        if mode == 'windows':
            if _HAS_EXPANDVARS and _expand_custom:
                return _expand_custom(text, environ=env, var_symbol='%', surrounded_vars_only=True, escape_char='').strip()
            return text.strip()
    except Exception:
        return os.path.expandvars(text).strip()
    return text.strip()

def normalize_and_expand_command_args(command: str, args: list[str], env: dict[str, str], expand_mode: str) -> tuple[str, list[str]]:
    expanded_command = expand_text(command or '', env, expand_mode)
    expanded_args = [expand_text(a, env, expand_mode) for a in args or []]
    return (expanded_command, expanded_args)

def split_embedded_args(expanded_command: str, current_args: list[str], windows_semantics: bool) -> tuple[str, list[str]]:
    if not current_args and (' ' in expanded_command or '\t' in expanded_command):
        parts = shlex.split(expanded_command, posix=not windows_semantics)
        if parts:
            return (parts[0], parts[1:])
    return (expanded_command, current_args)

def resolve_executable_path(cmd_command: str) -> str | None:
    candidate = (cmd_command or '').strip().strip('"').strip("'")
    if not candidate:
        return None
    if os.path.isabs(candidate) or os.path.sep in candidate:
        return candidate if os.path.exists(candidate) else shutil.which(candidate)
    return shutil.which(candidate)
