from pathlib import Path
import pytest
from sgscanner.loader import SkillIngester, IngestionError

@pytest.fixture
def example_skills_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills'

@pytest.fixture
def loader():
    return SkillIngester()

def test_load_safe_calculator(loader, example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    skill = loader.ingest(skill_dir)
    assert skill.name == 'simple-formatter'
    assert 'format' in skill.description.lower()
    assert skill.manifest.license == 'MIT'
    assert len(skill.files) > 0
    python_files = [f for f in skill.files if f.file_type == 'python']
    assert len(python_files) > 0

def test_load_malicious_skill(loader, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    skill = loader.ingest(skill_dir)
    assert skill.name == 'data-exfiltrator'
    assert len(skill.files) > 0

def test_load_nonexistent_skill(loader, tmp_path):
    with pytest.raises(IngestionError):
        loader.ingest(tmp_path / 'nonexistent')

def test_load_directory_without_skill_md(loader, tmp_path):
    empty_dir = tmp_path / 'empty'
    empty_dir.mkdir()
    with pytest.raises(IngestionError):
        loader.ingest(empty_dir)

def test_skill_file_discovery(loader, example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    skill = loader.ingest(skill_dir)
    assert len(skill.files) >= 2
    file_types = [f.file_type for f in skill.files]
    assert 'markdown' in file_types
    assert 'python' in file_types

def test_manifest_parsing(loader, example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    skill = loader.ingest(skill_dir)
    assert skill.manifest.name == 'simple-formatter'
    assert skill.manifest.description is not None
    assert skill.manifest.license == 'MIT'
    assert skill.manifest.allowed_tools is not None
    assert isinstance(skill.manifest.allowed_tools, list)

def test_allowed_tools_comma_separated_string_is_split(loader, tmp_path):
    skill_dir = tmp_path / 'comma-tools-skill'
    skill_dir.mkdir()
    (skill_dir / 'SKILL.md').write_text('---\nname: comma-tools-skill\ndescription: Test skill for allowed-tools parsing.\nallowed-tools: Read, Grep, Glob\n---\n\n# Comma Tools Skill\n', encoding='utf-8')
    skill = loader.ingest(skill_dir)
    assert skill.manifest.allowed_tools == ['Read', 'Grep', 'Glob']

def test_instruction_body_extraction(loader, example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    skill = loader.ingest(skill_dir)
    assert len(skill.instruction_body) > 0
    assert 'Formatter' in skill.instruction_body or 'format' in skill.instruction_body.lower()

def test_skill_discovery_under_dot_claude_directory(loader, tmp_path):
    skill_dir = tmp_path / '.claude' / 'skills' / 'my-skill'
    skill_dir.mkdir(parents=True)
    (skill_dir / 'SKILL.md').write_text('---\nname: my-skill\ndescription: A test skill that proves file discovery works under .claude.\nallowed-tools: [Read]\n---\n\n# My Skill\n\nSee [helper.py](helper.py).\n', encoding='utf-8')
    (skill_dir / 'helper.py').write_text("print('hello')\n", encoding='utf-8')
    skill = loader.ingest(skill_dir)
    rel_paths = sorted([f.relative_path for f in skill.files])
    assert 'SKILL.md' in rel_paths
    assert 'helper.py' in rel_paths

def test_codex_skills_metadata_short_description(loader, tmp_path):
    skill_dir = tmp_path / 'codex-skill'
    skill_dir.mkdir()
    (skill_dir / 'SKILL.md').write_text('---\nname: codex-skill\ndescription: Description that helps Codex select the skill\nmetadata:\n  short-description: Optional user-facing description\nlicense: MIT\n---\n\n# Codex Skill\n\nThis is a Codex Skills format skill.\n', encoding='utf-8')
    skill = loader.ingest(skill_dir)
    assert skill.manifest.name == 'codex-skill'
    assert skill.manifest.description == 'Description that helps Codex select the skill'
    assert skill.manifest.license == 'MIT'
    assert skill.manifest.metadata is not None
    assert skill.manifest.metadata.get('short-description') == 'Optional user-facing description'
    assert skill.manifest.short_description == 'Optional user-facing description'

def test_codex_skills_directory_structure(loader, tmp_path):
    skill_dir = tmp_path / 'codex-structured-skill'
    skill_dir.mkdir()
    (skill_dir / 'SKILL.md').write_text('---\nname: structured-skill\ndescription: A skill with Codex Skills directory structure\n---\n\n# Structured Skill\n', encoding='utf-8')
    (skill_dir / 'scripts').mkdir()
    (skill_dir / 'scripts' / 'main.py').write_text("print('hello')\n", encoding='utf-8')
    (skill_dir / 'references').mkdir()
    (skill_dir / 'references' / 'data.json').write_text('{"key": "value"}\n', encoding='utf-8')
    (skill_dir / 'assets').mkdir()
    (skill_dir / 'assets' / 'template.txt').write_text('Template content\n', encoding='utf-8')
    skill = loader.ingest(skill_dir)
    rel_paths = {f.relative_path for f in skill.files}
    assert 'SKILL.md' in rel_paths
    assert 'scripts/main.py' in rel_paths
    assert 'references/data.json' in rel_paths
    assert 'assets/template.txt' in rel_paths
    file_types = {f.relative_path: f.file_type for f in skill.files}
    assert file_types['scripts/main.py'] == 'python'
    assert file_types['references/data.json'] == 'other'
    assert file_types['assets/template.txt'] == 'other'
