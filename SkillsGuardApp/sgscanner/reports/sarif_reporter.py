import json
from typing import Any
from ..models import Finding, ScanSummary, ScanResult, Severity

class SARIFReporter:
    SARIF_VERSION = '2.1.0'
    SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
    SEVERITY_TO_LEVEL = {RiskLevel.CRITICAL: 'error', RiskLevel.HIGH: 'error', RiskLevel.MEDIUM: 'warning', RiskLevel.LOW: 'note', RiskLevel.INFO: 'note', RiskLevel.SAFE: 'none'}

    def __init__(self, tool_name: str='skill-scanner', tool_version: str='1.0.0'):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate_report(self, data: ScanResult | ScanSummary) -> str:
        if isinstance(data, ScanResult):
            sarif = self._generate_from_scan_result(data)
        else:
            sarif = self._generate_from_report(data)
        return json.dumps(sarif, indent=2, default=str)

    def _generate_from_scan_result(self, result: ScanResult) -> dict[str, Any]:
        rules = self._extract_rules(result.findings)
        results = self._convert_findings(result.findings, result.skill_directory)
        return {'$schema': self.SARIF_SCHEMA, 'version': self.SARIF_VERSION, 'runs': [{'tool': self._create_tool_component(rules), 'results': results, 'invocations': [{'executionSuccessful': True, 'endTimeUtc': result.timestamp.isoformat() + 'Z'}]}]}

    def _generate_from_report(self, report: ScanSummary) -> dict[str, Any]:
        all_findings = []
        for scan_result in report.scan_results:
            all_findings.extend(scan_result.findings)
        rules = self._extract_rules(all_findings)
        all_results = []
        for scan_result in report.scan_results:
            results = self._convert_findings(scan_result.findings, scan_result.skill_directory)
            all_results.extend(results)
        return {'$schema': self.SARIF_SCHEMA, 'version': self.SARIF_VERSION, 'runs': [{'tool': self._create_tool_component(rules), 'results': all_results, 'invocations': [{'executionSuccessful': True, 'endTimeUtc': report.timestamp.isoformat() + 'Z'}]}]}

    def _create_tool_component(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        return {'driver': {'name': self.tool_name, 'version': self.tool_version, 'informationUri': 'https://github.com/skillsguard-ai-defense/skill-scanner', 'rules': rules}}

    def _extract_rules(self, findings: list[Finding]) -> list[dict[str, Any]]:
        seen_rules: set[str] = set()
        rules = []
        for finding in findings:
            if finding.rule_id in seen_rules:
                continue
            seen_rules.add(finding.rule_id)
            rule = {'id': finding.rule_id, 'name': finding.rule_id.replace('_', ' ').title(), 'shortDescription': {'text': finding.title}, 'fullDescription': {'text': finding.description}, 'defaultConfiguration': {'level': self.SEVERITY_TO_LEVEL.get(finding.severity, 'warning')}, 'properties': {'category': finding.category.value, 'severity': finding.severity.value, 'tags': [finding.category.value, 'security']}}
            if finding.remediation:
                rule['help'] = {'text': finding.remediation, 'markdown': f'**Remediation**: {finding.remediation}'}
            rules.append(rule)
        return rules

    def _convert_findings(self, findings: list[Finding], base_path: str) -> list[dict[str, Any]]:
        results = []
        for finding in findings:
            result = {'ruleId': finding.rule_id, 'level': self.SEVERITY_TO_LEVEL.get(finding.severity, 'warning'), 'message': {'text': finding.description}, 'properties': {'category': finding.category.value, 'severity': finding.severity.value}}
            if finding.file_path:
                location = {'physicalLocation': {'artifactLocation': {'uri': finding.file_path, 'uriBaseId': '%SRCROOT%'}}}
                if finding.line_number:
                    location['physicalLocation']['region'] = {'startLine': finding.line_number}
                    if finding.snippet:
                        location['physicalLocation']['region']['snippet'] = {'text': finding.snippet}
                result['locations'] = [location]
            if finding.remediation:
                result['fixes'] = [{'description': {'text': finding.remediation}}]
            result['fingerprints'] = {'primaryLocationLineHash': finding.id}
            results.append(result)
        return results

    def save_report(self, data: ScanResult | ScanSummary, output_path: str):
        report_json = self.generate_report(data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_json)
