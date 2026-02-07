from tabulate import tabulate
from ..models import ScanSummary, ScanResult, Severity

class TableReporter:

    def __init__(self, format_style: str='grid', show_snippets: bool=False):
        self.format_style = format_style
        self.show_snippets = show_snippets

    def generate_report(self, data: ScanResult | ScanSummary) -> str:
        if isinstance(data, ScanResult):
            return self._generate_scan_result_report(data)
        else:
            return self._generate_multi_skill_report(data)

    def _generate_scan_result_report(self, result: ScanResult) -> str:
        lines = []
        lines.append('=' * 80)
        lines.append(f'Agent Skill Security Scan: {result.skill_name}')
        lines.append('=' * 80)
        lines.append('')
        summary_data = [['Skill', result.skill_name], ['Status', '[OK] SAFE' if result.is_safe else '[FAIL] ISSUES FOUND'], ['Max Severity', result.max_severity.value], ['Total Findings', len(result.findings)], ['Scan Duration', f'{result.scan_duration_seconds:.2f}s']]
        lines.append(tabulate(summary_data, tablefmt=self.format_style))
        lines.append('')
        if result.findings:
            severity_data = [['Critical', len(result.filter_by_risk(RiskLevel.CRITICAL))], ['High', len(result.filter_by_risk(RiskLevel.HIGH))], ['Medium', len(result.filter_by_risk(RiskLevel.MEDIUM))], ['Low', len(result.filter_by_risk(RiskLevel.LOW))], ['Info', len(result.filter_by_risk(RiskLevel.INFO))]]
            lines.append('Findings by Severity:')
            lines.append(tabulate(severity_data, headers=['Severity', 'Count'], tablefmt=self.format_style))
            lines.append('')
            lines.append('Detailed Findings:')
            findings_data = []
            for finding in result.findings:
                location = finding.file_path or 'N/A'
                if finding.line_number:
                    location += f':{finding.line_number}'
                findings_data.append([finding.severity.value, finding.category.value, finding.title[:40] + '...' if len(finding.title) > 40 else finding.title, location[:30] + '...' if len(location) > 30 else location])
            lines.append(tabulate(findings_data, headers=['Severity', 'Category', 'Title', 'Location'], tablefmt=self.format_style))
            if self.show_snippets:
                lines.append('')
                lines.append('=' * 80)
                lines.append('CODE EVIDENCE')
                lines.append('=' * 80)
                lines.append('')
                for i, finding in enumerate(result.findings, 1):
                    lines.append(f'Finding #{i}: {finding.title}')
                    lines.append(f'  Location: {finding.file_path}:{finding.line_number or 'N/A'}')
                    lines.append(f'  Severity: {finding.severity.value}')
                    if finding.snippet:
                        lines.append(f'  Code: {finding.snippet}')
                    if finding.remediation:
                        lines.append(f'  Fix: {finding.remediation}')
                    lines.append('')
        else:
            lines.append('[OK] No security issues found!')
        lines.append('')
        return '\n'.join(lines)

    def _generate_multi_skill_report(self, report: ScanSummary) -> str:
        lines = []
        lines.append('=' * 80)
        lines.append('Agent Skills Security Scan Report')
        lines.append('=' * 80)
        lines.append('')
        summary_data = [['Total Skills Scanned', report.total_skills_scanned], ['Safe Skills', report.safe_count], ['Total Findings', report.total_findings], ['Critical', report.critical_count], ['High', report.high_count], ['Medium', report.medium_count], ['Low', report.low_count], ['Info', report.info_count]]
        lines.append(tabulate(summary_data, tablefmt=self.format_style))
        lines.append('')
        lines.append('Skills Overview:')
        skills_data = []
        for result in report.scan_results:
            skills_data.append([result.skill_name, '[OK] SAFE' if result.is_safe else '[FAIL] ISSUES', result.max_severity.value, len(result.findings), len(result.filter_by_risk(RiskLevel.CRITICAL)), len(result.filter_by_risk(RiskLevel.HIGH))])
        lines.append(tabulate(skills_data, headers=['Skill', 'Status', 'Max Severity', 'Total', 'Critical', 'High'], tablefmt=self.format_style))
        lines.append('')
        return '\n'.join(lines)

    def save_report(self, data: ScanResult | ScanSummary, output_path: str):
        report_table = self.generate_report(data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_table)
