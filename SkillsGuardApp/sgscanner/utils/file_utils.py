from pathlib import Path

def read_file_safe(file_path: Path, max_size_mb: int=10) -> str | None:
    try:
        size_bytes = file_path.stat().st_size
        max_bytes = max_size_mb * 1024 * 1024
        if size_bytes > max_bytes:
            return None
        with open(file_path, encoding='utf-8') as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None

def get_file_type(file_path: Path) -> str:
    suffix = file_path.suffix.lower()
    type_mapping = {'.py': 'python', '.sh': 'bash', '.bash': 'bash', '.md': 'markdown', '.markdown': 'markdown', '.exe': 'binary', '.so': 'binary', '.dylib': 'binary', '.dll': 'binary', '.bin': 'binary'}
    return type_mapping.get(suffix, 'other')

def is_binary_file(file_path: Path) -> bool:
    return get_file_type(file_path) == 'binary'
