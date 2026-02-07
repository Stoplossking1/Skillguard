from pathlib import Path
from typing import Any
import yara

class YaraScanner:

    def __init__(self, rules_dir: Path | None=None):
        if rules_dir is None:
            from ...data import YARA_RULES_DIR
            rules_dir = YARA_RULES_DIR
        self.rules_dir = Path(rules_dir)
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        if not self.rules_dir.exists():
            raise FileNotFoundError(f'YARA rules directory not found: {self.rules_dir}')
        yara_files = list(self.rules_dir.glob('*.yara'))
        if not yara_files:
            raise FileNotFoundError(f'No .yara files found in {self.rules_dir}')
        rules_dict = {}
        for yara_file in yara_files:
            namespace = yara_file.stem
            rules_dict[namespace] = str(yara_file)
        try:
            self.rules = yara.compile(filepaths=rules_dict)
        except yara.SyntaxError as e:
            raise RuntimeError(f'Failed to compile YARA rules: {e}')

    def scan_content(self, content: str, file_path: str | None=None) -> list[dict[str, Any]]:
        if not self.rules:
            return []
        matches = []
        try:
            yara_matches = self.rules.match(data=content)
            for match in yara_matches:
                meta = {'rule_name': match.rule, 'namespace': match.namespace, 'tags': match.tags, 'meta': match.meta}
                matched_strings = []
                for string in match.strings:
                    for instance in string.instances:
                        line_num = content[:instance.offset].count('\n') + 1
                        line_start = content.rfind('\n', 0, instance.offset) + 1
                        line_end = content.find('\n', instance.offset)
                        if line_end == -1:
                            line_end = len(content)
                        line_content = content[line_start:line_end].strip()
                        matched_strings.append({'identifier': string.identifier, 'offset': instance.offset, 'matched_data': instance.matched_data.decode('utf-8', errors='ignore'), 'line_number': line_num, 'line_content': line_content})
                matches.append({'rule_name': match.rule, 'namespace': match.namespace, 'file_path': file_path, 'meta': meta, 'strings': matched_strings})
        except yara.Error as e:
            print(f'Warning: YARA scanning error: {e}')
        return matches

    def scan_file(self, file_path: Path) -> list[dict[str, Any]]:
        try:
            with open(file_path, encoding='utf-8') as f:
                content = f.read()
            return self.scan_content(content, str(file_path))
        except (OSError, UnicodeDecodeError) as e:
            print(f'Warning: Could not read file {file_path}: {e}')
            return []

    def get_loaded_rules(self) -> list[str]:
        if not self.rules:
            return []
        yara_files = list(self.rules_dir.glob('*.yara'))
        return [f.stem for f in yara_files]
