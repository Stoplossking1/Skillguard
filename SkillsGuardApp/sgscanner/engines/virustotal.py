import hashlib
import logging
from pathlib import Path
import httpx
from ..models import Finding, Severity, Skill, ThreatCategory
from .base import ScanEngine
from .registry import register_engine
logger = logging.getLogger('sg.' + __name__)

@register_engine(name='virustotal_detector', description='Binary file scanning via VirusTotal hash lookups', aliases=('virustotal_analyzer',), metadata={'requires_api_key': True, 'expose_cli': True, 'order': 25})
class VirusTotalEngine(ScanEngine):
    engine_id = 'virustotal_detector'
    BINARY_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tiff', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.tgz', '.exe', '.dll', '.so', '.dylib', '.bin', '.com', '.wasm', '.class', '.jar', '.war'}
    EXCLUDED_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.cs', '.vb', '.md', '.txt', '.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg', '.xml', '.html', '.css', '.scss', '.sass', '.less', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.sql', '.graphql', '.proto', '.thrift', '.rst', '.org', '.adoc', '.tex'}

    def __init__(self, api_key: str | None=None, enabled: bool=True, upload_files: bool=False):
        super().__init__()
        self.api_key = api_key
        self.enabled = enabled and api_key is not None
        self.upload_files = upload_files
        self.validated_binary_files = []
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.session = httpx.Client()
        if not self.api_key:
            logger.warning('VirusTotal API key is missing!')
        if self.api_key:
            self.session.headers.update({'x-apikey': self.api_key, 'Accept': 'application/json'})
            logger.info('VirusTotal API key configured (length: %d)', len(self.api_key))
        else:
            logger.warning('VirusTotal analyzer initialized without API key')

    def run(self, skill: Skill) -> list[Finding]:
        if not self.enabled:
            return []
        findings = []
        validated_files = []
        binary_files = [f for f in skill.files if self._is_binary_file(f.relative_path)]
        for skill_file in binary_files:
            try:
                file_path = Path(skill.directory) / skill_file.relative_path
                file_hash = self._calculate_sha256(file_path)
                logger.info('Checking file: %s (SHA256: %s)', skill_file.relative_path, file_hash)
                vt_result, hash_found = self._query_virustotal(file_hash)
                if hash_found:
                    total = vt_result.get('total_engines', 0)
                    malicious = vt_result.get('malicious', 0)
                    suspicious = vt_result.get('suspicious', 0)
                    if malicious > 0 or suspicious > 0:
                        logger.warning('Found in VT database: %d malicious, %d suspicious out of %d vendors', malicious, suspicious, total)
                    else:
                        logger.info('Found in VT database: %d/%d vendors flagged (file appears safe)', malicious, total)
                        validated_files.append(skill_file.relative_path)
                    if vt_result.get('permalink'):
                        logger.info('ScanSummary: %s', vt_result['permalink'])
                    if malicious > 0:
                        findings.append(self._create_finding(skill_file=skill_file, file_hash=file_hash, vt_result=vt_result))
                elif self.upload_files:
                    logger.warning('Hash not found in VT database - uploading for analysis')
                    vt_result = self._upload_and_scan(file_path, file_hash)
                    if vt_result:
                        if vt_result.get('malicious', 0) > 0:
                            findings.append(self._create_finding(skill_file=skill_file, file_hash=file_hash, vt_result=vt_result))
                        else:
                            validated_files.append(skill_file.relative_path)
                else:
                    logger.warning('Hash not found in VT database - upload disabled, cannot scan unknown file')
            except Exception as e:
                logger.warning('VirusTotal scan failed for %s: %s', skill_file.relative_path, e)
                continue
        self.validated_binary_files = validated_files
        return findings

    def _is_binary_file(self, file_path: str) -> bool:
        path = Path(file_path)
        ext = path.suffix.lower()
        if ext in self.EXCLUDED_EXTENSIONS:
            return False
        if ext in self.BINARY_EXTENSIONS:
            return True
        return False

    def _calculate_sha256(self, file_path: Path) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _query_virustotal(self, file_hash: str) -> tuple[dict | None, bool]:
        try:
            response = self.session.get(f'{self.base_url}/files/{file_hash}', timeout=10)
            if response.status_code == 404:
                return (None, False)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                gui_url = f'https://www.virustotal.com/gui/file/{file_hash}'
                result = {'malicious': stats.get('malicious', 0), 'suspicious': stats.get('suspicious', 0), 'undetected': stats.get('undetected', 0), 'harmless': stats.get('harmless', 0), 'total_engines': sum(stats.values()), 'scan_date': data.get('data', {}).get('attributes', {}).get('last_analysis_date'), 'permalink': gui_url}
                return (result, True)
            if response.status_code == 429:
                logger.warning('VirusTotal rate limit exceeded. Please wait before retrying.')
            else:
                logger.warning('VirusTotal API returned status %d', response.status_code)
            return (None, False)
        except httpx.RequestError as e:
            logger.warning('VirusTotal API request failed: %s', e)
            return (None, False)

    def _upload_and_scan(self, file_path: Path, file_hash: str) -> dict | None:
        try:
            import time
            file_size = file_path.stat().st_size
            if file_size > 32 * 1024 * 1024:
                logger.warning('File too large to upload to VT: %s (%d bytes)', file_path.name, file_size)
                return None
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                response = self.session.post(f'{self.base_url}/files', files=files, timeout=60)
            if response.status_code != 200:
                logger.warning('File upload failed with status %d', response.status_code)
                return None
            upload_data = response.json()
            analysis_id = upload_data.get('data', {}).get('id')
            if not analysis_id:
                logger.warning('No analysis ID returned from upload')
                return None
            logger.info('File uploaded successfully. Analysis ID: %s', analysis_id)
            max_retries = 6
            for attempt in range(max_retries):
                time.sleep(10)
                analysis_response = self.session.get(f'{self.base_url}/analyses/{analysis_id}', timeout=10)
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    status = analysis_data.get('data', {}).get('attributes', {}).get('status')
                    stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                    if status == 'completed':
                        result, _ = self._query_virustotal(file_hash)
                        if result and result.get('total_engines', 0) > 0:
                            logger.info('Analysis complete: %d/%d vendors scanned', result.get('malicious', 0), result.get('total_engines', 0))
                            return result
                    else:
                        total_scans = sum(stats.values()) if stats else 0
                        logger.info('Status: %s (%d engines scanned, attempt %d/%d)', status, total_scans, attempt + 1, max_retries)
                else:
                    logger.warning('Analysis query failed with status %d', analysis_response.status_code)
            logger.warning('Analysis still processing after %d seconds', max_retries * 10)
            result, _ = self._query_virustotal(file_hash)
            return result
        except httpx.RequestError as e:
            logger.warning('File upload to VirusTotal failed: %s', e)
            return None
        except Exception as e:
            logger.warning('Unexpected error during file upload: %s', e)
            return None

    def _create_finding(self, skill_file, file_hash: str, vt_result: dict) -> Finding:
        malicious_count = vt_result.get('malicious', 0)
        total_engines = vt_result.get('total_engines', 0)
        if total_engines > 0:
            detection_ratio = malicious_count / total_engines
            if detection_ratio >= 0.3:
                severity = RiskLevel.CRITICAL
            elif detection_ratio >= 0.1:
                severity = RiskLevel.HIGH
            else:
                severity = RiskLevel.MEDIUM
        else:
            severity = RiskLevel.MEDIUM
        return Issue(id=f'VT_{file_hash[:8]}', rule_id='VIRUSTOTAL_MALICIOUS_FILE', category=ThreatClass.MALWARE, severity=severity, title=f'Malicious file detected: {skill_file.relative_path}', description=f'VirusTotal detected this file as malicious. {malicious_count}/{total_engines} security vendors flagged this file. SHA256: {file_hash}', file_path=skill_file.relative_path, line_number=None, snippet=f'File hash: {file_hash}', remediation='Remove this file from the skill package. Binary files flagged by multiple antivirus engines should not be included.', engine='virustotal', metadata={'confidence': 0.95 if malicious_count >= 5 else 0.8, 'references': [f'https://www.virustotal.com/gui/file/{file_hash}'], 'file_hash': file_hash})
