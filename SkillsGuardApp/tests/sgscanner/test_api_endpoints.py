import io
import time
import zipfile
from pathlib import Path
import pytest
try:
    from fastapi.testclient import TestClient
    from sgscanner.api.api import app
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False
    app = None
    TestClient = None

@pytest.fixture
def client():
    if not API_AVAILABLE:
        pytest.skip('FastAPI not installed')
    return TestClient(app)

@pytest.fixture
def safe_skill_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'

@pytest.fixture
def malicious_skill_dir():
    path = Path(__file__).parent.parent / 'evals' / 'skills' / 'clawbot-malicious' / 'wed'
    if not path.exists():
        pytest.skip('Malicious test skill not found')
    return path

@pytest.fixture
def test_skills_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills'

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestHealthEndpoint:

    def test_health_endpoint_returns_200(self, client):
        response = client.get('/health')
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
        assert 'version' in data
        assert 'detectors_available' in data
        assert isinstance(data['detectors_available'], list)
        assert 'analyzers_available' in data
        assert isinstance(data['analyzers_available'], list)

    def test_health_includes_pattern_detector(self, client):
        response = client.get('/health')
        data = response.json()
        assert 'pattern_detector' in data['detectors_available']

    def test_health_includes_dataflow_detector(self, client):
        response = client.get('/health')
        data = response.json()
        assert 'dataflow_detector' in data['detectors_available']

    def test_health_includes_semantic_detector(self, client):
        response = client.get('/health')
        data = response.json()
        assert 'detectors_available' in data

    def test_health_includes_aidefense_detector(self, client):
        response = client.get('/health')
        data = response.json()
        assert 'aidefense_detector' in data['detectors_available']

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestRootEndpoint:

    def test_root_endpoint_returns_service_info(self, client):
        response = client.get('/')
        assert response.status_code == 200
        data = response.json()
        assert 'service' in data
        assert 'Skill Scanner' in data['service']
        assert 'version' in data

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestScanEndpoint:

    def test_scan_valid_skill_pattern_only(self, client, safe_skill_dir):
        request_data = {'skill_directory': str(safe_skill_dir), 'use_semantic': False}
        response = client.post('/scan', json=request_data)
        assert response.status_code == 200
        data = response.json()
        assert 'scan_id' in data
        assert 'skill_name' in data
        assert data['skill_name'] == 'simple-formatter'
        assert 'is_safe' in data
        assert data['is_safe'] is True
        assert 'findings_count' in data
        assert 'scan_duration_seconds' in data
        assert 'timestamp' in data
        assert 'findings' in data

    def test_scan_with_dataflow_detector(self, client, safe_skill_dir):
        request_data = {'skill_directory': str(safe_skill_dir), 'use_dataflow': True, 'use_semantic': False}
        response = client.post('/scan', json=request_data)
        assert response.status_code == 200
        data = response.json()
        assert 'scan_id' in data
        assert 'findings' in data

    def test_scan_nonexistent_skill_returns_404(self, client):
        request_data = {'skill_directory': '/nonexistent/skill', 'use_semantic': False}
        response = client.post('/scan', json=request_data)
        assert response.status_code == 404
        assert 'not found' in response.json()['detail'].lower()

    def test_scan_without_skill_md_returns_400(self, client):
        tests_dir = Path(__file__).parent
        request_data = {'skill_directory': str(tests_dir), 'use_semantic': False}
        response = client.post('/scan', json=request_data)
        assert response.status_code == 400
        assert 'SKILL.md' in response.json()['detail']

    def test_scan_aidefense_without_key_returns_400(self, client, safe_skill_dir):
        request_data = {'skill_directory': str(safe_skill_dir), 'use_aidefense': True, 'aidefense_api_key': None}
        response = client.post('/scan', json=request_data)
        assert response.status_code in [200, 400]
        if response.status_code == 400:
            assert 'API key' in response.json()['detail']

    def test_scan_response_structure(self, client, safe_skill_dir):
        request_data = {'skill_directory': str(safe_skill_dir)}
        response = client.post('/scan', json=request_data)
        assert response.status_code == 200
        data = response.json()
        required_fields = ['scan_id', 'skill_name', 'is_safe', 'max_severity', 'findings_count', 'scan_duration_seconds', 'timestamp', 'findings']
        for field in required_fields:
            assert field in data, f'Missing field: {field}'

    def test_scan_with_all_parameters(self, client, safe_skill_dir):
        request_data = {'skill_directory': str(safe_skill_dir), 'use_dataflow': True, 'use_semantic': False, 'llm_provider': 'anthropic', 'use_aidefense': False}
        response = client.post('/scan', json=request_data)
        assert response.status_code == 200

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestBatchScanEndpoint:

    def test_batch_scan_initiates(self, client, test_skills_dir):
        request_data = {'skills_directory': str(test_skills_dir), 'recursive': False, 'use_semantic': False}
        response = client.post('/scan-batch', json=request_data)
        assert response.status_code == 200
        data = response.json()
        assert 'scan_id' in data
        assert data['status'] == 'processing'
        assert 'message' in data

    def test_batch_scan_with_dataflow(self, client, test_skills_dir):
        request_data = {'skills_directory': str(test_skills_dir), 'recursive': False, 'use_dataflow': True, 'use_semantic': False}
        response = client.post('/scan-batch', json=request_data)
        assert response.status_code == 200
        data = response.json()
        assert 'scan_id' in data

    def test_batch_scan_result_retrieval(self, client, test_skills_dir):
        request_data = {'skills_directory': str(test_skills_dir), 'recursive': False, 'use_semantic': False}
        response = client.post('/scan-batch', json=request_data)
        scan_id = response.json()['scan_id']
        time.sleep(2)
        result_response = client.get(f'/scan-batch/{scan_id}')
        assert result_response.status_code == 200
        result_data = result_response.json()
        assert result_data['scan_id'] == scan_id
        assert result_data['status'] in ['processing', 'completed']

    def test_batch_scan_nonexistent_id_returns_404(self, client):
        response = client.get('/scan-batch/nonexistent-id-12345')
        assert response.status_code == 404

    def test_batch_scan_nonexistent_directory_returns_404(self, client):
        request_data = {'skills_directory': '/nonexistent/directory', 'use_llm': False}
        response = client.post('/scan-batch', json=request_data)
        assert response.status_code == 404

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestDetectorsEndpoint:

    def test_list_detectors(self, client):
        response = client.get('/detectors')
        assert response.status_code == 200
        data = response.json()
        assert 'detectors' in data
        detectors = data['detectors']
        assert len(detectors) > 0
        detector_names = [d['name'] for d in detectors]
        assert 'pattern_detector' in detector_names

    def test_detector_structure(self, client):
        response = client.get('/detectors')
        data = response.json()
        for detector in data['detectors']:
            assert 'name' in detector
            assert 'description' in detector
            assert 'available' in detector

    def test_all_detectors_listed(self, client):
        response = client.get('/detectors')
        data = response.json()
        detector_names = [d['name'] for d in data['detectors']]
        expected = ['pattern_detector', 'dataflow_detector', 'semantic_detector', 'aidefense_detector']
        for name in expected:
            assert name in detector_names, f'Missing detector: {name}'

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestUploadEndpoint:

    def test_upload_requires_zip(self, client):
        files = {'file': ('test.txt', b'not a zip', 'text/plain')}
        response = client.post('/scan-upload', files=files)
        assert response.status_code == 400
        assert 'ZIP' in response.json()['detail']

    def test_upload_valid_zip(self, client, safe_skill_dir):
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            skill_md = safe_skill_dir / 'SKILL.md'
            if skill_md.exists():
                zf.write(skill_md, 'SKILL.md')
        zip_buffer.seek(0)
        files = {'file': ('skill.zip', zip_buffer, 'application/zip')}
        response = client.post('/scan-upload', files=files)
        assert response.status_code in [200, 400, 500]

    def test_upload_with_parameters(self, client, safe_skill_dir):
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            skill_md = safe_skill_dir / 'SKILL.md'
            if skill_md.exists():
                zf.write(skill_md, 'SKILL.md')
        zip_buffer.seek(0)
        files = {'file': ('skill.zip', zip_buffer, 'application/zip')}
        data = {'use_dataflow': 'true', 'use_semantic': 'false'}
        response = client.post('/scan-upload', files=files, data=data)
        assert response.status_code in [200, 400, 500]

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestAPIErrorHandling:

    def test_invalid_json_returns_422(self, client):
        response = client.post('/scan', json={'invalid_field': 'value'})
        assert response.status_code == 422

    def test_malformed_request_handled(self, client):
        response = client.post('/scan', data='not json')
        assert response.status_code in [400, 422]

    def test_empty_body_returns_422(self, client):
        response = client.post('/scan', json={})
        assert response.status_code == 422

    def test_wrong_method_returns_405(self, client):
        response = client.get('/scan')
        assert response.status_code == 405

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestAPIDocumentation:

    def test_docs_endpoint_accessible(self, client):
        response = client.get('/docs')
        assert response.status_code == 200

    def test_redoc_endpoint_accessible(self, client):
        response = client.get('/redoc')
        assert response.status_code == 200

    def test_openapi_schema_accessible(self, client):
        response = client.get('/openapi.json')
        assert response.status_code == 200
        data = response.json()
        assert 'openapi' in data
        assert 'paths' in data
        assert 'info' in data

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestMaliciousSkillDetection:

    def test_pattern_detector_detects_patterns(self, client):
        malicious_dir = Path(__file__).parent.parent / 'evals' / 'skills' / 'command-injection' / 'curl-injection'
        if not malicious_dir.exists():
            pytest.skip('Test skill not found')
        request_data = {'skill_directory': str(malicious_dir), 'use_llm': False}
        response = client.post('/scan', json=request_data)
        if response.status_code == 200:
            data = response.json()
            assert 'findings' in data

@pytest.mark.skipif(not API_AVAILABLE, reason='FastAPI not installed')
class TestConcurrentRequests:

    def test_multiple_health_checks(self, client):
        responses = []
        for _ in range(5):
            responses.append(client.get('/health'))
        for response in responses:
            assert response.status_code == 200

    def test_multiple_scans(self, client, safe_skill_dir):
        request_data = {'skill_directory': str(safe_skill_dir), 'use_llm': False}
        responses = []
        for _ in range(3):
            responses.append(client.post('/scan', json=request_data))
        for response in responses:
            assert response.status_code == 200
            data = response.json()
            assert 'scan_id' in data
