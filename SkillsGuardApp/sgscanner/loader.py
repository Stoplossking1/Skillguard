import re
from pathlib import Path
import frontmatter
from .models import Skill, SkillFile, SkillManifest

class IngestionError(Exception):
    pass

class SkillIngester:
    PYTHON_EXTENSIONS = {'.py'}
    BASH_EXTENSIONS = {'.sh', '.bash'}
    MARKDOWN_EXTENSIONS = {'.md', '.markdown'}
    BINARY_EXTENSIONS = {'.exe', '.so', '.dylib', '.dll', '.bin'}

    def __init__(self, max_file_size_mb: int=10):
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

    def ingest(self, skill_directory: Path) -> Skill:
        if not isinstance(skill_directory, Path):
            skill_directory = Path(skill_directory)
        if not skill_directory.exists():
            raise IngestionError(f'Skill directory does not exist: {skill_directory}')
        if not skill_directory.is_dir():
            raise IngestionError(f'Path is not a directory: {skill_directory}')
        skill_md_path = skill_directory / 'SKILL.md'
        if not skill_md_path.exists():
            raise IngestionError(f'SKILL.md not found in {skill_directory}')
        manifest, instruction_body = self._parse_skill_md(skill_md_path)
        files = self._discover_files(skill_directory)
        referenced_files = self._extract_referenced_files(instruction_body)
        return Skill(directory=skill_directory, manifest=manifest, skill_md_path=skill_md_path, instruction_body=instruction_body, files=files, referenced_files=referenced_files)

    def _parse_skill_md(self, skill_md_path: Path) -> tuple[SkillManifest, str]:
        try:
            with open(skill_md_path, encoding='utf-8') as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            raise IngestionError(f'Failed to read SKILL.md: {e}')
        try:
            post = frontmatter.loads(content)
            metadata = post.metadata
            body = post.content
        except Exception as e:
            raise IngestionError(f'Failed to parse YAML frontmatter: {e}')
        if 'name' not in metadata:
            raise IngestionError('SKILL.md missing required field: name')
        if 'description' not in metadata:
            raise IngestionError('SKILL.md missing required field: description')
        metadata_field = None
        if 'metadata' in metadata and isinstance(metadata['metadata'], dict):
            metadata_field = metadata['metadata']
        else:
            known_fields = ['name', 'description', 'license', 'compatibility', 'allowed-tools', 'allowed_tools', 'metadata', 'disable-model-invocation', 'disable_model_invocation']
            metadata_field = {k: v for k, v in metadata.items() if k not in known_fields}
            if not metadata_field:
                metadata_field = None
        disable_model_invocation = metadata.get('disable-model-invocation')
        if disable_model_invocation is None:
            disable_model_invocation = metadata.get('disable_model_invocation', False)
        manifest = SkillManifest(name=metadata['name'], description=metadata['description'], license=metadata.get('license'), compatibility=metadata.get('compatibility'), allowed_tools=metadata.get('allowed-tools') or metadata.get('allowed_tools'), metadata=metadata_field, disable_model_invocation=bool(disable_model_invocation))
        return (manifest, body)

    def _discover_files(self, skill_directory: Path) -> list[SkillFile]:
        files = []
        for path in skill_directory.rglob('*'):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(skill_directory).parts
            if any((part.startswith('.') for part in rel_parts)):
                continue
            if '__pycache__' in rel_parts:
                continue
            relative_path = str(path.relative_to(skill_directory))
            file_type = self._determine_file_type(path)
            size_bytes = path.stat().st_size
            content = None
            if size_bytes < self.max_file_size_bytes and file_type != 'binary':
                try:
                    with open(path, encoding='utf-8') as f:
                        content = f.read()
                except (OSError, UnicodeDecodeError):
                    file_type = 'binary'
            skill_file = SkillFile(path=path, relative_path=relative_path, file_type=file_type, content=content, size_bytes=size_bytes)
            files.append(skill_file)
        return files

    def _determine_file_type(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix in self.PYTHON_EXTENSIONS:
            return 'python'
        elif suffix in self.BASH_EXTENSIONS:
            return 'bash'
        elif suffix in self.MARKDOWN_EXTENSIONS:
            return 'markdown'
        elif suffix in self.BINARY_EXTENSIONS:
            return 'binary'
        else:
            return 'other'

    def _extract_referenced_files(self, instruction_body: str) -> list[str]:
        references = []
        markdown_links = re.findall('\\[([^\\]]+)\\]\\(([^\\)]+)\\)', instruction_body)
        for _, link in markdown_links:
            if not link.startswith(('http://', 'https://', 'ftp://', '#')):
                references.append(link)
        see_patterns = re.findall('(?:see|refer to|check|read)\\s+[`\'\\"]([A-Za-z0-9_\\-./]+\\.(?:md|py|sh|txt))[`\'\\"]', instruction_body, re.IGNORECASE)
        references.extend(see_patterns)
        script_patterns = re.findall('(?:run|execute|invoke)\\s+([A-Za-z0-9_\\-./]+\\.(?:py|sh))', instruction_body, re.IGNORECASE)
        references.extend(script_patterns)
        reference_directives = re.findall('@reference:\\s*([A-Za-z0-9_\\-./]+)', instruction_body, re.IGNORECASE)
        references.extend(reference_directives)
        include_patterns = re.findall('(?:include|import|load):\\s*([A-Za-z0-9_\\-./]+\\.(?:md|py|sh|txt|yaml|json))', instruction_body, re.IGNORECASE)
        references.extend(include_patterns)
        code_file_refs = re.findall('(?:from|import)\\s+([A-Za-z0-9_]+)\\s', instruction_body)
        for ref in code_file_refs:
            if not ref.startswith(('os', 'sys', 're', 'json', 'yaml', 'typing')):
                references.append(f'{ref}.py')
        asset_patterns = re.findall('(?:references|assets|templates)/([A-Za-z0-9_\\-./]+)', instruction_body)
        for pattern in asset_patterns:
            references.append(f'references/{pattern}')
            references.append(f'assets/{pattern}')
            references.append(f'templates/{pattern}')
        return list(set(references))

    def extract_references_from_file(self, file_path: Path, content: str) -> list[str]:
        references = []
        suffix = file_path.suffix.lower()
        if suffix in ('.md', '.markdown'):
            references.extend(self._extract_referenced_files(content))
        elif suffix == '.py':
            import_patterns = re.findall('^from\\s+([A-Za-z0-9_.]+)\\s+import', content, re.MULTILINE)
            relative_imports = re.findall('^from\\s+\\.([A-Za-z0-9_.]*)\\s+import', content, re.MULTILINE)
            for imp in import_patterns:
                if not imp.startswith(('os', 'sys', 're', 'json', 'pathlib', 'typing', 'collections')):
                    parts = imp.split('.')
                    references.append(f'{parts[0]}.py')
            for imp in relative_imports:
                if imp:
                    references.append(f'{imp}.py')
        elif suffix in ('.sh', '.bash'):
            source_patterns = re.findall('(?:source|\\.)\\s+([A-Za-z0-9_\\-./]+\\.(?:sh|bash))', content)
            references.extend(source_patterns)
        return list(set(references))

def ingest(skill_directory: Path, max_file_size_mb: int=10) -> Skill:
    loader = SkillIngester(max_file_size_mb=max_file_size_mb)
    return loader.ingest(skill_directory)
