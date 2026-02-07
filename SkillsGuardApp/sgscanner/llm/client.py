"""Unified LLM client for SGScanner.

Combines prompt construction, provider configuration, request handling,
and response parsing into a single cohesive module.
"""
import asyncio
import importlib.util
import json
import os
import secrets
import warnings
from pathlib import Path
from typing import Any

from ..models import Skill

# ── Optional dependency detection ────────────────────────────────────

try:
    GOOGLE_GENAI_AVAILABLE = importlib.util.find_spec("google.genai") is not None
except (ImportError, ModuleNotFoundError):
    GOOGLE_GENAI_AVAILABLE = False

try:
    LITELLM_AVAILABLE = importlib.util.find_spec("litellm") is not None
except (ImportError, ModuleNotFoundError):
    LITELLM_AVAILABLE = False

try:
    from litellm import acompletion
except (ImportError, ModuleNotFoundError):
    acompletion = None

try:
    from google import genai
except (ImportError, ModuleNotFoundError):
    genai = None

warnings.filterwarnings("ignore", message=".*Pydantic serializer warnings.*")
warnings.filterwarnings("ignore", message=".*Expected `Message`.*")
warnings.filterwarnings("ignore", message=".*Expected `StreamingChoices`.*")
warnings.filterwarnings("ignore", message=".*close_litellm_async_clients.*")


# ── Provider Configuration ───────────────────────────────────────────

class ProviderConfig:
    """Configuration for an LLM provider (OpenAI, Bedrock, Gemini, etc.)."""

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
        api_version: str | None = None,
        aws_region: str | None = None,
        aws_profile: str | None = None,
        aws_session_token: str | None = None,
    ):
        self.model = model
        self.base_url = base_url
        self.api_version = api_version
        self.aws_region = aws_region or os.getenv("AWS_REGION", "us-east-1")
        self.aws_profile = aws_profile or os.getenv("AWS_PROFILE")
        self.aws_session_token = aws_session_token or os.getenv("AWS_SESSION_TOKEN")

        model_lower = model.lower()
        self.is_bedrock = "bedrock/" in model or model_lower.startswith("bedrock/")
        self.is_gemini = "gemini" in model_lower or model_lower.startswith("gemini/")
        self.is_azure = model_lower.startswith("azure/") or "azure" in model_lower
        self.is_vertex = model_lower.startswith("vertex_ai/") or "vertex" in model_lower
        self.is_ollama = model_lower.startswith("ollama/")
        self.is_openrouter = model_lower.startswith("openrouter/")
        self.use_google_sdk = False

        if self.is_vertex:
            if not LITELLM_AVAILABLE:
                raise ImportError(
                    "LiteLLM is required for Vertex AI. Install with: pip install litellm"
                )
            self.model = model
        elif self.is_gemini and GOOGLE_GENAI_AVAILABLE:
            self.use_google_sdk = True
            self.model = self._normalize_gemini_model_name(model)
        elif self.is_gemini and not GOOGLE_GENAI_AVAILABLE:
            raise ImportError(
                "For Gemini models, either LiteLLM or google-genai is required."
            )
        elif not LITELLM_AVAILABLE:
            raise ImportError(
                "LiteLLM is required for LLM engine. Install with: pip install litellm"
            )
        elif self.is_gemini and not model.startswith("gemini/"):
            model_name = model.replace("gemini-", "").replace("gemini/", "")
            self.model = f"gemini/{model_name}"
        else:
            self.model = model

        self.api_key = self._resolve_api_key(api_key)

    def _resolve_api_key(self, api_key: str | None) -> str | None:
        if api_key is not None:
            return api_key
        if self.is_vertex:
            return os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        elif self.is_ollama:
            return None
        return os.getenv("SG_LLM_API_KEY") or os.getenv("SG_LLM_API_KEY")

    def _normalize_gemini_model_name(self, model: str) -> str:
        model_name = model.replace("gemini/", "").replace("models/", "")
        model_mapping = {
            "gemini-1.5-pro": "gemini-pro-latest",
            "gemini-1.5-flash": "gemini-flash-latest",
        }
        if model_name in model_mapping:
            model_name = model_mapping[model_name]
        if not model_name.startswith("gemini-"):
            model_name = f"gemini-{model_name}"
        if not model_name.startswith("models/"):
            model_name = f"models/{model_name}"
        return model_name

    def validate(self) -> None:
        """Raise ValueError if required credentials are missing."""
        if not self.is_bedrock and not self.api_key:
            raise ValueError(f"API key required for model {self.model}")

    def get_request_params(self) -> dict:
        """Build provider-specific request parameters."""
        params: dict[str, Any] = {}
        if self.api_key:
            if self.is_gemini:
                if not os.getenv("GEMINI_API_KEY"):
                    os.environ["GEMINI_API_KEY"] = self.api_key
            else:
                params["api_key"] = self.api_key
        if self.base_url:
            params["api_base"] = self.base_url
        if self.api_version:
            params["api_version"] = self.api_version
        if self.is_bedrock:
            if self.aws_region:
                params["aws_region_name"] = self.aws_region
            if self.aws_session_token:
                params["aws_session_token"] = self.aws_session_token
            if self.aws_profile:
                params["aws_profile_name"] = self.aws_profile
        return params


# ── Prompt Builder ───────────────────────────────────────────────────

class PromptBuilder:
    """Constructs security analysis prompts for the LLM."""

    def __init__(self):
        self.protection_rules = ""
        self.threat_analysis_prompt = ""
        self._load_prompts()

    def _load_prompts(self):
        prompts_dir = Path(__file__).parent.parent / "data" / "prompts"
        try:
            protection_file = prompts_dir / "boilerplate_protection_rule_prompt.md"
            threat_file = prompts_dir / "skill_threat_analysis_prompt.md"
            self.protection_rules = (
                protection_file.read_text(encoding="utf-8")
                if protection_file.exists()
                else "You are a security analyst analyzing agent skills."
            )
            self.threat_analysis_prompt = (
                threat_file.read_text(encoding="utf-8")
                if threat_file.exists()
                else "Analyze for security threats."
            )
        except Exception:
            self.protection_rules = "You are a security analyst analyzing agent skills."
            self.threat_analysis_prompt = "Analyze for security threats."

    def build_threat_analysis_prompt(
        self,
        skill_name: str,
        description: str,
        manifest_details: str,
        instruction_body: str,
        code_files: str,
        referenced_files: str,
    ) -> tuple[str, bool]:
        """Build the full analysis prompt with injection protection tags."""
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"

        analysis_content = (
            f"Skill Name: {skill_name}\n"
            f"Description: {description}\n\n"
            f"YAML Manifest Details:\n{manifest_details}\n\n"
            f"Instruction Body (SKILL.md markdown):\n{instruction_body}\n\n"
            f"Script Files (Python/Bash):\n{code_files}\n\n"
            f"Referenced Files:\n{referenced_files}\n"
        )

        injection_detected = start_tag in analysis_content or end_tag in analysis_content
        protected_rules = self.protection_rules.replace(
            "<!---UNTRUSTED_INPUT_START--->", start_tag
        ).replace("<!---UNTRUSTED_INPUT_END--->", end_tag)

        prompt = f"{protected_rules}\n\n{self.threat_analysis_prompt}\n\n{start_tag}\n{analysis_content}\n{end_tag}\n"
        return prompt.strip(), injection_detected

    def format_manifest(self, manifest) -> str:
        """Format a skill manifest for inclusion in the prompt."""
        lines = [
            f"- name: {manifest.name}",
            f"- description: {manifest.description}",
            f"- license: {manifest.license or 'Not specified'}",
            f"- compatibility: {manifest.compatibility or 'Not specified'}",
            f"- allowed-tools: {', '.join(manifest.allowed_tools) if manifest.allowed_tools else 'Not specified'}",
        ]
        if manifest.metadata:
            lines.append(f"- additional metadata: {manifest.metadata}")
        return "\n".join(lines)

    def format_code_files(self, skill: Skill) -> str:
        """Format script files for inclusion in the prompt."""
        lines: list[str] = []
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if content:
                truncated = content[:1500]
                if len(content) > 1500:
                    truncated += f"\n... (truncated, total {len(content)} chars)"
                lines.append(f"**File: {skill_file.relative_path}**")
                lines.append("```" + skill_file.file_type)
                lines.append(truncated)
                lines.append("```")
                lines.append("")
        return "\n".join(lines) if lines else "No script files found."

    def format_referenced_files(self, skill: Skill, max_file_size: int = 2000) -> str:
        """Format referenced files for inclusion in the prompt."""
        if not skill.referenced_files:
            return "No referenced files."
        lines: list[str] = [
            f"Files referenced in instructions: {', '.join(skill.referenced_files)}",
            "",
        ]
        for ref_file_path in skill.referenced_files:
            if ".." in ref_file_path or ref_file_path.startswith("/"):
                lines.append(
                    f"**Referenced File: {ref_file_path}** (blocked: path traversal attempt)"
                )
                lines.append("")
                continue

            full_path = skill.directory / ref_file_path
            if not full_path.exists():
                alt_paths = [
                    skill.directory / "rules" / Path(ref_file_path).name,
                    skill.directory / "references" / ref_file_path,
                    skill.directory / "assets" / ref_file_path,
                    skill.directory / "templates" / ref_file_path,
                ]
                for alt in alt_paths:
                    if alt.exists():
                        full_path = alt
                        break

            if not full_path.exists():
                lines.append(f"**Referenced File: {ref_file_path}** (not found)")
                lines.append("")
                continue

            if not self._is_path_within_directory(full_path, skill.directory):
                lines.append(
                    f"**Referenced File: {ref_file_path}** (blocked: outside skill directory)"
                )
                lines.append("")
                continue

            try:
                content = full_path.read_text(encoding="utf-8")
                truncated = content[:max_file_size]
                if len(content) > max_file_size:
                    truncated += f"\n... (truncated, total {len(content)} chars)"
                suffix = full_path.suffix.lower()
                file_type = "markdown" if suffix in (".md", ".markdown") else "text"
                lines.append(f"**Referenced File: {ref_file_path}**")
                lines.append(f"```{file_type}")
                lines.append(truncated)
                lines.append("```")
                lines.append("")
            except Exception as e:
                lines.append(f"**Referenced File: {ref_file_path}** (error reading: {e})")
                lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _is_path_within_directory(path: Path, directory: Path) -> bool:
        try:
            return path.resolve().is_relative_to(directory.resolve())
        except (ValueError, OSError):
            return False


# ── Request Handler ──────────────────────────────────────────────────

class LLMRequestHandler:
    """Handles async LLM API requests with retry and rate-limit logic."""

    def __init__(
        self,
        provider_config: ProviderConfig,
        max_tokens: int = 4000,
        temperature: float = 0.0,
        max_retries: int = 3,
        rate_limit_delay: float = 2.0,
        timeout: int = 120,
    ):
        self.provider_config = provider_config
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout
        self.response_schema = self._load_response_schema()

    def _load_response_schema(self) -> dict[str, Any] | None:
        try:
            schema_path = (
                Path(__file__).parent.parent / "data" / "prompts" / "llm_response_schema.json"
            )
            if schema_path.exists():
                return json.loads(schema_path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return None

    def _sanitize_schema_for_google(self, schema: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(schema, dict):
            return schema
        sanitized: dict[str, Any] = {}
        for key, value in schema.items():
            if key == "additionalProperties":
                continue
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_schema_for_google(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_schema_for_google(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized

    async def make_request(self, messages: list[dict[str, str]], context: str = "") -> str:
        """Send a request to the configured LLM provider."""
        if self.provider_config.use_google_sdk:
            prompt_parts: list[str] = []
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "system":
                    prompt_parts.append(f"System Instructions:\n{content}\n")
                elif role == "user":
                    prompt_parts.append(f"User Request:\n{content}\n")
            return await self._make_google_sdk_request("\n".join(prompt_parts).strip())
        else:
            return await self._make_litellm_request(messages, context)

    async def _make_litellm_request(
        self, messages: list[dict[str, str]], context: str
    ) -> str:
        last_exception: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                request_params = {
                    "model": self.provider_config.model,
                    "messages": messages,
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "timeout": self.timeout,
                    **self.provider_config.get_request_params(),
                }
                if self.response_schema:
                    request_params["response_format"] = {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "security_analysis_response",
                            "schema": self.response_schema,
                            "strict": True,
                        },
                    }
                response = await acompletion(**request_params)
                return response.choices[0].message.content
            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()
                rate_keywords = ["rate limit", "quota", "too many requests", "429", "throttling"]
                if any(kw in error_msg for kw in rate_keywords):
                    if attempt < self.max_retries:
                        delay = 2**attempt * self.rate_limit_delay
                        await asyncio.sleep(delay)
                        continue
                break
        raise last_exception  # type: ignore[misc]

    async def _make_google_sdk_request(self, prompt: str) -> str:
        last_exception: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                client = genai.Client(api_key=self.provider_config.api_key)
                config_dict: dict[str, Any] = {
                    "max_output_tokens": self.max_tokens,
                    "temperature": self.temperature,
                }
                if self.response_schema:
                    config_dict["response_mime_type"] = "application/json"
                    config_dict["response_schema"] = self._sanitize_schema_for_google(
                        self.response_schema
                    )
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: client.models.generate_content(
                        model=self.provider_config.model,
                        contents=prompt,
                        config=config_dict,
                    ),
                )
                if hasattr(response, "text") and response.text:
                    return response.text
                elif hasattr(response, "candidates") and response.candidates:
                    candidate = response.candidates[0]
                    if hasattr(candidate, "content") and candidate.content:
                        parts = getattr(candidate.content, "parts", [])
                        if parts and hasattr(parts[0], "text"):
                            return parts[0].text
                return str(getattr(response, "content", response))
            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()
                if "quota" in error_msg or "rate limit" in error_msg or "429" in error_msg:
                    if attempt < self.max_retries:
                        await asyncio.sleep(self.rate_limit_delay * 2**attempt)
                        continue
                raise
        raise last_exception  # type: ignore[misc]


# ── Response Parser ──────────────────────────────────────────────────

class ResponseParser:
    """Extracts structured JSON from LLM response text."""

    @staticmethod
    def parse(response_content: str) -> dict[str, Any]:
        """Parse a JSON response, handling markdown code fences."""
        if not response_content or not response_content.strip():
            raise ValueError("Empty response from LLM")

        # Try direct JSON parse first
        try:
            return json.loads(response_content.strip())
        except json.JSONDecodeError:
            pass

        # Strip markdown code fences
        text = response_content
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            text = text[start:end].strip()

        # Find outermost JSON object by brace matching
        start_idx = text.find("{")
        if start_idx != -1:
            brace_count = 0
            for i in range(start_idx, len(text)):
                if text[i] == "{":
                    brace_count += 1
                elif text[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        return json.loads(text[start_idx : i + 1])

        raise ValueError(f"Could not parse JSON from response: {response_content[:200]}")
