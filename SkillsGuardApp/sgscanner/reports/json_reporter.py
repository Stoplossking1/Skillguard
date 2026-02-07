import json
from ..models import ScanSummary, ScanResult

class JSONReporter:

    def __init__(self, pretty: bool=True):
        self.pretty = pretty

    def generate_report(self, data: ScanResult | ScanSummary) -> str:
        report_dict = data.serialize()
        if self.pretty:
            return json.dumps(report_dict, indent=2, default=str)
        else:
            return json.dumps(report_dict, default=str)

    def save_report(self, data: ScanResult | ScanSummary, output_path: str):
        report_json = self.generate_report(data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_json)
