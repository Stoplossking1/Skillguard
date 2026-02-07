import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
try:
    from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, UploadFile
    from pydantic import BaseModel, Field
    MULTIPART_AVAILABLE = True
except ImportError:
    raise ImportError('API server requires FastAPI. Install with: pip install fastapi uvicorn python-multipart')
from ..engines.pattern import PatternEngine
from ..engines.registry import ENGINE_REGISTRY
from ..models import ScanResult
from ..pipeline.orchestrator import ScanOrchestrator
try:
    from ..engines.llm_engine import LLMEngine
    SEMANTIC_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    SEMANTIC_AVAILABLE = False
    LLMEngine = None
try:
    from ..engines.dataflow import DataflowEngine
    DATAFLOW_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    DATAFLOW_AVAILABLE = False
    DataflowEngine = None
try:
    from ..engines.aidefense import AIDefenseEngine
    AIDEFENSE_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    AIDEFENSE_AVAILABLE = False
    AIDefenseEngine = None
try:
    from ..engines.meta import MetaEngine, apply_meta_filtering
    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaEngine = None
    apply_meta_filtering = None
router = APIRouter()
scan_results_cache = {}

class InspectRequest(BaseModel):
    skill_directory: str = Field(..., description='Path to skill directory')
    use_semantic: bool = Field(False, description='Enable semantic detector')
    use_semantic: bool = Field(False, description='Enable semantic detector (preferred)')
    llm_provider: str | None = Field('anthropic', description='LLM provider (anthropic or openai)')
    use_dataflow: bool = Field(False, description='Enable dataflow detector')
    use_dataflow: bool = Field(False, description='Enable dataflow detector (preferred)')
    use_aidefense: bool = Field(False, description='Enable AI Defense detector')
    aidefense_api_key: str | None = Field(None, description='AI Defense API key')
    enable_meta: bool = Field(False, description='Enable meta detector for false positive filtering')

class InspectResponse(BaseModel):
    scan_id: str
    skill_name: str
    is_safe: bool
    max_severity: str
    findings_count: int
    scan_duration_seconds: float
    timestamp: str
    findings: list[dict]

class StatusResponse(BaseModel):
    status: str
    version: str
    detectors_available: list[str]
    analyzers_available: list[str]

class BatchInspectRequest(BaseModel):
    skills_directory: str
    recursive: bool = False
    use_semantic: bool = False
    use_semantic: bool = False
    llm_provider: str | None = 'anthropic'
    use_dataflow: bool = False
    use_dataflow: bool = False
    use_aidefense: bool = False
    aidefense_api_key: str | None = None
    enable_meta: bool = Field(False, description='Enable meta-analysis')

@router.get('/', response_model=dict)
async def root():
    return {'service': 'Skill Scanner API', 'version': '0.2.0', 'docs': '/docs', 'health': '/health'}

@router.get('/health', response_model=StatusResponse)
async def health_check():
    detectors = [entry['name'] for entry in ENGINE_REGISTRY.list_api_entries()]
    return StatusResponse(status='healthy', version='0.2.0', detectors_available=detectors, analyzers_available=detectors)

@router.post('/inspect', response_model=InspectResponse)
async def inspect(request: InspectRequest):
    import asyncio
    import concurrent.futures
    import os
    skill_dir = Path(request.skill_directory)
    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f'Skill directory not found: {skill_dir}')
    if not (skill_dir / 'SKILL.md').exists():
        raise HTTPException(status_code=400, detail='SKILL.md not found in directory')

    def run_scan():
        from ..engines.base import ScanEngine
        detectors: list[ScanEngine] = [PatternEngine()]
        use_dataflow = bool(getattr(request, 'use_dataflow', False) or request.use_dataflow)
        use_semantic = bool(getattr(request, 'use_semantic', False) or request.use_semantic)
        if use_dataflow and DATAFLOW_AVAILABLE:
            dataflow_detector = DataflowEngine(use_static_analysis=True)
            detectors.append(dataflow_detector)
        if use_semantic and SEMANTIC_AVAILABLE:
            llm_model = os.getenv('SG_LLM_MODEL')
            provider_str = request.llm_provider or 'anthropic'
            if llm_model:
                semantic_detector = LLMEngine(model=llm_model)
            else:
                semantic_detector = LLMEngine(provider=provider_str)
            detectors.append(semantic_detector)
        if request.use_aidefense and AIDEFENSE_AVAILABLE:
            api_key = request.aidefense_api_key or os.getenv('AI_DEFENSE_API_KEY')
            if not api_key:
                raise ValueError('AI Defense API key required')
            aidefense_detector = AIDefenseEngine(api_key=api_key)
            detectors.append(aidefense_detector)
        scanner = ScanOrchestrator(engines=detectors)
        return scanner.inspect(skill_dir)
    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await loop.run_in_executor(executor, run_scan)
        if request.enable_meta and META_AVAILABLE and (len(result.findings) > 0):
            try:
                from ..loader import SkillIngester
                meta_detector = MetaEngine()
                loader = SkillIngester()
                skill = loader.ingest(skill_dir)
                import asyncio as async_lib

                def run_meta():
                    return async_lib.run(meta_detector.analyze_with_findings(skill=skill, findings=result.findings, engines_used=result.engines_used))
                with concurrent.futures.ThreadPoolExecutor() as meta_executor:
                    meta_result = await loop.run_in_executor(meta_executor, run_meta)
                filtered_findings = apply_meta_filtering(original_findings=result.findings, meta_result=meta_result, skill=skill)
                result.findings = filtered_findings
                result.engines_used.append('meta_detector')
            except Exception as meta_error:
                print(f'Warning: Meta-analysis failed: {meta_error}')
        scan_id = str(uuid.uuid4())
        return InspectResponse(scan_id=scan_id, skill_name=result.skill_name, is_safe=result.is_safe, max_severity=result.max_severity.value, findings_count=len(result.findings), scan_duration_seconds=result.scan_duration_seconds, timestamp=result.timestamp.isoformat(), findings=[f.serialize() for f in result.findings])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Scan failed: {str(e)}')

@router.post('/inspect-upload')
async def scan_uploaded_skill(file: UploadFile=File(..., description='ZIP file containing skill package'), use_semantic: bool=Query(False, description='Enable LLM analyzer'), llm_provider: str=Query('anthropic', description='LLM provider'), use_dataflow: bool=Query(False, description='Enable behavioral analyzer'), use_aidefense: bool=Query(False, description='Enable AI Defense analyzer'), aidefense_api_key: str | None=Query(None, description='AI Defense API key')):
    if not file.filename or not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail='File must be a ZIP archive')
    temp_dir = Path(tempfile.mkdtemp(prefix='sgscanner_'))
    try:
        zip_path = temp_dir / file.filename
        with open(zip_path, 'wb') as f:
            content = await file.read()
            f.write(content)
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir / 'extracted')
        extracted_dir = temp_dir / 'extracted'
        skill_dirs = list(extracted_dir.rglob('SKILL.md'))
        if not skill_dirs:
            raise HTTPException(status_code=400, detail='No SKILL.md found in uploaded archive')
        skill_dir = skill_dirs[0].parent
        request = InspectRequest(skill_directory=str(skill_dir), use_semantic=use_semantic, llm_provider=llm_provider, use_dataflow=use_dataflow, use_aidefense=use_aidefense, aidefense_api_key=aidefense_api_key)
        result = await scan_skill(request)
        return result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@router.post('/inspect-batch')
async def scan_batch(request: BatchInspectRequest, background_tasks: BackgroundTasks):
    skills_dir = Path(request.skills_directory)
    if not skills_dir.exists():
        raise HTTPException(status_code=404, detail=f'Skills directory not found: {skills_dir}')
    scan_id = str(uuid.uuid4())
    scan_results_cache[scan_id] = {'status': 'processing', 'started_at': datetime.now().isoformat(), 'result': None}
    background_tasks.add_task(run_batch_scan, scan_id, skills_dir, request.recursive, request.use_semantic, request.use_semantic, request.llm_provider, request.use_dataflow, request.use_dataflow, request.use_aidefense, request.aidefense_api_key)
    return {'scan_id': scan_id, 'status': 'processing', 'message': 'Batch scan started. Use GET /inspect-batch/{scan_id} to check status.'}

@router.get('/inspect-batch/{scan_id}')
async def get_batch_scan_result(scan_id: str):
    if scan_id not in scan_results_cache:
        raise HTTPException(status_code=404, detail='Scan ID not found')
    cached = scan_results_cache[scan_id]
    if cached['status'] == 'processing':
        return {'scan_id': scan_id, 'status': 'processing', 'started_at': cached['started_at']}
    elif cached['status'] == 'completed':
        return {'scan_id': scan_id, 'status': 'completed', 'started_at': cached['started_at'], 'completed_at': cached.get('completed_at'), 'result': cached['result']}
    else:
        return {'scan_id': scan_id, 'status': 'error', 'error': cached.get('error', 'Unknown error')}

def run_batch_scan(scan_id: str, skills_dir: Path, recursive: bool, use_semantic: bool, use_semantic: bool, llm_provider: str | None, use_dataflow: bool=False, use_dataflow: bool=False, use_aidefense: bool=False, aidefense_api_key: str | None=None):
    try:
        import os
        from ..engines.base import ScanEngine
        detectors: list[ScanEngine] = [PatternEngine()]
        use_dataflow_flag = use_dataflow or use_dataflow
        use_semantic_flag = use_semantic or use_semantic
        if use_dataflow_flag and DATAFLOW_AVAILABLE:
            try:
                dataflow_detector = DataflowEngine(use_static_analysis=True)
                detectors.append(dataflow_detector)
            except Exception:
                pass
        if use_semantic_flag and SEMANTIC_AVAILABLE:
            try:
                llm_model = os.getenv('SG_LLM_MODEL')
                provider_str = llm_provider or 'anthropic'
                if llm_model:
                    semantic_detector = LLMEngine(model=llm_model)
                else:
                    semantic_detector = LLMEngine(provider=provider_str)
                detectors.append(semantic_detector)
            except Exception:
                pass
        if use_aidefense and AIDEFENSE_AVAILABLE:
            try:
                api_key = aidefense_api_key or os.getenv('AI_DEFENSE_API_KEY')
                if not api_key:
                    raise ValueError('AI Defense API key required (set AI_DEFENSE_API_KEY or pass aidefense_api_key)')
                aidefense_detector = AIDefenseEngine(api_key=api_key)
                detectors.append(aidefense_detector)
            except ValueError:
                raise
            except Exception:
                pass
        scanner = ScanOrchestrator(engines=detectors)
        report = scanner.inspect_directory(skills_dir, recursive=recursive)
        scan_results_cache[scan_id] = {'status': 'completed', 'started_at': scan_results_cache[scan_id]['started_at'], 'completed_at': datetime.now().isoformat(), 'result': report.serialize()}
    except Exception as e:
        scan_results_cache[scan_id] = {'status': 'error', 'started_at': scan_results_cache[scan_id]['started_at'], 'error': str(e)}

@router.get('/engines')
async def list_engines():
    return {'analyzers': ENGINE_REGISTRY.list_api_entries()}

@router.get('/engines')
async def list_engines():
    return {'detectors': ENGINE_REGISTRY.list_api_entries()}
