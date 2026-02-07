from dataclasses import dataclass, field
from typing import Any
from ..context_extractor import SkillScriptContext

@dataclass
class CrossFileCorrelation:
    threat_type: str
    severity: str
    files_involved: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ''

class CrossFileAnalyzer:

    def __init__(self):
        self.file_contexts: dict[str, SkillScriptContext] = {}
        self.correlations: list[CrossFileCorrelation] = []

    def add_file_context(self, file_name: str, context: SkillScriptContext):
        self.file_contexts[file_name] = context

    def analyze_correlations(self) -> list[CrossFileCorrelation]:
        self.correlations = []
        self._detect_exfiltration_chain()
        self._detect_credential_network_separation()
        self._detect_env_var_exfiltration_chain()
        return self.correlations

    def _detect_exfiltration_chain(self):
        has_collection = []
        has_encoding = []
        has_network = []
        for file_name, context in self.file_contexts.items():
            if context.has_env_var_access or context.has_credential_access:
                has_collection.append(file_name)
            if any(('base64' in call or 'encode' in call for call in context.all_function_calls)):
                has_encoding.append(file_name)
            if context.has_network:
                has_network.append(file_name)
        if has_collection and has_network and (len(self.file_contexts) > 1):
            correlation = CrossFileCorrelation(threat_type='exfiltration_chain', severity='CRITICAL', files_involved=list(set(has_collection + has_encoding + has_network)), evidence={'collection_files': has_collection, 'encoding_files': has_encoding, 'network_files': has_network}, description=f'Multi-file exfiltration chain detected: {', '.join(has_collection)} collect data → {(', '.join(has_encoding) if has_encoding else 'encode')} → {', '.join(has_network)} transmit to network')
            self.correlations.append(correlation)

    def _detect_credential_network_separation(self):
        credential_files = []
        network_files = []
        for file_name, context in self.file_contexts.items():
            if context.has_credential_access:
                credential_files.append(file_name)
            if context.has_network:
                network_files.append(file_name)
        if credential_files and network_files and (not set(credential_files) & set(network_files)):
            correlation = CrossFileCorrelation(threat_type='credential_network_separation', severity='HIGH', files_involved=credential_files + network_files, evidence={'credential_files': credential_files, 'network_files': network_files}, description=f'Credential access ({', '.join(credential_files)}) separated from network transmission ({', '.join(network_files)}) - possible evasion technique')
            self.correlations.append(correlation)

    def _detect_env_var_exfiltration_chain(self):
        env_var_files = []
        network_files = []
        for file_name, context in self.file_contexts.items():
            if context.has_env_var_access:
                env_var_files.append(file_name)
            if context.has_network:
                network_files.append(file_name)
        if env_var_files and network_files:
            if not set(env_var_files) & set(network_files):
                severity = 'CRITICAL'
                desc = f'Environment variable harvesting ({', '.join(env_var_files)}) separated from network transmission ({', '.join(network_files)}) across files'
            else:
                severity = 'CRITICAL'
                desc = f'Environment variable access with network calls in {', '.join(env_var_files)}'
            correlation = CrossFileCorrelation(threat_type='env_var_exfiltration', severity=severity, files_involved=list(set(env_var_files + network_files)), evidence={'env_var_files': env_var_files, 'network_files': network_files}, description=desc)
            self.correlations.append(correlation)

    def get_critical_correlations(self) -> list[CrossFileCorrelation]:
        return [c for c in self.correlations if c.severity == 'CRITICAL']
