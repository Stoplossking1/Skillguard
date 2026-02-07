import re
from ..models import Finding, ScanSummary, ScanResult, Severity

class MarkdownReporter:

    def __init__(self, detailed: bool=True):
        self.detailed = detailed

    def generate_report(self, data: ScanResult | ScanSummary) -> str:
        if isinstance(data, ScanResult):
            return self._generate_scan_result_report(data)
        else:
            return self._generate_multi_skill_report(data)

    def _generate_scan_result_report(self, result: ScanResult) -> str:
        lines = []
        lines.append('# Agent Skill Security Scan Report')
        lines.append('')
        lines.append(f'**Skill:** {result.skill_name}')
        lines.append(f'**Directory:** {result.skill_directory}')
        lines.append(f'**Status:** {('[OK] SAFE' if result.is_safe else '[FAIL] ISSUES FOUND')}')
        lines.append(f'**Max Severity:** {result.max_severity.value}')
        lines.append(f'**Scan Duration:** {result.scan_duration_seconds:.2f}s')
        lines.append(f'**Timestamp:** {result.timestamp.isoformat()}')
        lines.append('')
        lines.append('## Summary')
        lines.append('')
        lines.append(f'- **Total Findings:** {len(result.findings)}')
        lines.append(f'- **Critical:** {len(result.filter_by_risk(RiskLevel.CRITICAL))}')
        lines.append(f'- **High:** {len(result.filter_by_risk(RiskLevel.HIGH))}')
        lines.append(f'- **Medium:** {len(result.filter_by_risk(RiskLevel.MEDIUM))}')
        lines.append(f'- **Low:** {len(result.filter_by_risk(RiskLevel.LOW))}')
        lines.append(f'- **Info:** {len(result.filter_by_risk(RiskLevel.INFO))}')
        lines.append('')
        if result.findings:
            lines.append('## Findings')
            lines.append('')
            for severity in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
                findings = result.filter_by_risk(severity)
                if findings:
                    lines.append(f'### {severity.value} Severity')
                    lines.append('')
                    for finding in findings:
                        lines.extend(self._format_finding(finding))
                        lines.append('')
        else:
            lines.append('## [OK] No Issues Found')
            lines.append('')
            lines.append('This skill passed all security checks.')
            lines.append('')
        lines.append('## Analyzers')
        lines.append('')
        lines.append('The following analyzers were used:')
        lines.append('')
        for analyzer in result.engines_used:
            lines.append(f'- {analyzer}')
        lines.append('')
        return '\n'.join(lines)

    def _generate_multi_skill_report(self, report: ScanSummary) -> str:
        lines = []
        lines.append('# Agent Skills Security Scan Report')
        lines.append('')
        lines.append(f'**Timestamp:** {report.timestamp.isoformat()}')
        lines.append('')
        lines.append('## Summary')
        lines.append('')
        lines.append(f'- **Total Skills Scanned:** {report.total_skills_scanned}')
        lines.append(f'- **Safe Skills:** {report.safe_count}')
        lines.append(f'- **Total Findings:** {report.total_findings}')
        lines.append('')
        lines.append('### Findings by Severity')
        lines.append('')
        lines.append(f'- **Critical:** {report.critical_count}')
        lines.append(f'- **High:** {report.high_count}')
        lines.append(f'- **Medium:** {report.medium_count}')
        lines.append(f'- **Low:** {report.low_count}')
        lines.append(f'- **Info:** {report.info_count}')
        lines.append('')
        lines.append('## Skill Results')
        lines.append('')
        for result in report.scan_results:
            lines.append('\n---\n')
            status_icon = '[OK]' if result.is_safe else '[FAIL]'
            lines.append(f'### {status_icon} {result.skill_name}')
            lines.append('')
            lines.append(f'- **Max Severity:** {result.max_severity.value}')
            lines.append(f'- **Findings:** {len(result.findings)}')
            lines.append(f'- **Directory:** {result.skill_directory}')
            lines.append('')
            if self.detailed and result.findings:
                for finding in result.findings:
                    lines.extend(self._format_finding(finding, indent=1))
                    lines.append('')
        return '\n'.join(lines)

    def _format_finding(self, finding: Finding, indent: int=0) -> list:
        lines = []
        indent_str = '  ' * indent
        severity_prefix = {RiskLevel.CRITICAL: '[CRITICAL]', RiskLevel.HIGH: '[HIGH]', RiskLevel.MEDIUM: '[MEDIUM]', RiskLevel.LOW: '[LOW]', RiskLevel.INFO: '[INFO]'}
        prefix = severity_prefix.get(finding.severity, '[INFO]')
        lines.append(f'{indent_str}#### {prefix} {finding.title}')
        lines.append(f'{indent_str}')
        lines.append(f'{indent_str}**Severity:** {finding.severity.value}')
        lines.append(f'{indent_str}**Category:** {finding.category.value}')
        lines.append(f'{indent_str}**Rule ID:** {finding.rule_id}')
        if finding.file_path:
            location = f'{finding.file_path}'
            if finding.line_number:
                location += f':{finding.line_number}'
            lines.append(f'{indent_str}**Location:** {location}')
        lines.append(f'{indent_str}')
        lines.append(f'{indent_str}**Description:** {finding.description}')
        if self.detailed:
            if finding.snippet:
                lines.append(f'{indent_str}')
                lines.append(f'{indent_str}**Code Snippet:**')
                if not re.search('```', finding.snippet):
                    lines.append(f'{indent_str}```')
                for line in finding.snippet.splitlines():
                    lines.append(f'{indent_str}{line}')
                if not re.search('```', finding.snippet):
                    lines.append(f'{indent_str}```')
            if finding.remediation:
                lines.append(f'{indent_str}')
                lines.append(f'{indent_str}**Remediation:** {finding.remediation}')
        return lines

    def save_report(self, data: ScanResult | ScanSummary, output_path: str):
        report_md = self.generate_report(data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_md)
