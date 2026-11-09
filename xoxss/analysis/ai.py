"""Opt-in AI fallback for reflection contexts the payload corpus misses.

The scanner keeps its deterministic evidence policy: AI output is only ever a
*candidate payload*.  It still has to reflect with a surviving delimiter and,
when a browser is available, execute in the instrumented sink before a finding
is raised.

Configuration mirrors XSSRush:

* API key: ``--ai-key``, then ``XOXSS_AI_KEY``, ``OPENROUTER_API_KEY`` or
  ``XSSR_AI_KEY``, then a ``.env`` file next to the project/cwd.
* Endpoint: OpenRouter by default (``--ai-url`` overrides it).
* Model: ``deepseek/deepseek-chat`` by default (``--ai-model`` overrides it).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

DEFAULT_AI_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_AI_MODEL = "deepseek/deepseek-chat"
DEFAULT_AI_TIMEOUT = 60.0
ENV_KEYS = ("XOXSS_AI_KEY", "OPENROUTER_API_KEY", "XSSR_AI_KEY")

_DOTENV_KEYS = ("XOXSS_AI_KEY", "OPENROUTER_API_KEY", "XSSR_AI_KEY", "XOXSS_AI_MODEL")


def _read_dotenv(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key in _DOTENV_KEYS and value:
            values[key] = value
    return values


def resolve_ai_key(
    cli_key: Optional[str] = None,
    *,
    env: Optional[Dict[str, str]] = None,
    dotenv_paths: Optional[Sequence[Path]] = None,
) -> str:
    """Return the first configured API key, or an empty string."""
    candidate = str(cli_key or "").strip()
    if candidate:
        return candidate
    environment = env if env is not None else os.environ
    for name in ENV_KEYS:
        value = str(environment.get(name) or "").strip()
        if value:
            return value
    paths = list(dotenv_paths or [])
    if not paths:
        paths = [Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env"]
    seen = set()
    for path in paths:
        resolved = str(path)
        if resolved in seen:
            continue
        seen.add(resolved)
        if not path.is_file():
            continue
        values = _read_dotenv(path)
        for name in ENV_KEYS:
            if values.get(name):
                return values[name]
    return ""


def resolve_ai_model(default: str = DEFAULT_AI_MODEL, env: Optional[Dict[str, str]] = None) -> str:
    environment = env if env is not None else os.environ
    value = str(environment.get("XOXSS_AI_MODEL") or "").strip()
    return value or default


def build_system_prompt() -> str:
    """Breakout rules for the model.  Kept intentionally payload-focused."""
    return (
        "You are an automated web security analyzer auditing input reflection and "
        "context syntax boundaries.\n"
        "Your task is to analyze a reflection point where the standard canary payloads "
        "did not break out. Produce minimal proof-of-concept strings that trigger "
        "alert(1), confirm(1) or alert`1`.\n"
        "\n"
        "SYNTAX BREAKOUT RULES:\n"
        "1. Single-line JS comment (// ...): never close it with */; inject a newline "
        "(\\n, \\r, %0A, %0D, \\u2028, \\u2029) or </script> if < and > are allowed.\n"
        "2. Block JS comment (/* ... */): close it with */, then inject code and reopen "
        "a comment, e.g. */alert(1)/* or */alert(1)//.\n"
        "3. JavaScript expression/function argument: quotes are unnecessary; pass "
        "alert(1), confirm(1) or alert`1`; or close the call: 1);alert(1);//.\n"
        "4. Template literals (`...`): use ${alert(1)} or close with `+alert(1)+`.\n"
        "5. String literals: close with the matching quote then use +, - or ;, e.g. "
        "';alert(1);// or \"+alert(1)+\".\n"
        "6. JSON/object literals in <script>: </script><svg onload=alert(1)> breaks out "
        "regardless of the JSON structure; or close the string and inject a value.\n"
        "7. Inline event handlers and javascript: URIs: browsers decode HTML entities "
        "before JavaScript executes; &quot;, &apos;, &#x27; and &NewLine; can act as "
        "delimiters. Try &apos;;alert(1);// or );alert(1);//.\n"
        "8. Unquoted HTML attribute: no quote is needed; inject a space and an event "
        "handler, e.g. autofocus onfocus=alert(1).\n"
        "9. Quoted HTML attribute: close the tag with the matching quote and >, e.g. "
        "\"><svg onload=alert(1)>, or stay in the tag with an event handler.\n"
        "10. HTML comment / RCDATA elements: close with -->, </textarea>, </title>, "
        "</style> or </noscript>, then inject an active vector.\n"
        "\n"
        "FILTER COMPLIANCE:\n"
        "- Trust the character matrix. If < and > are filtered you cannot use HTML tags "
        "and must stay inside JavaScript.\n"
        "- If ( and ) are filtered use tagged templates (alert`1`) or throw.\n"
        "- If quotes are filtered use backticks, RegExp.source or raw numbers.\n"
        "- If spaces are filtered use / between attributes or tabs/newlines.\n"
        "- If dots are filtered use bracket notation: window['alert'](1).\n"
        "\n"
        "Respond ONLY with a valid JSON object in this exact shape:\n"
        '{"analysis": "1-2 sentence breakout explanation", "payloads": ["p1", "p2"]}\n'
        "Return 1 to 3 payloads. Do not wrap the response in markdown fences."
    )


def _matrix_groups(matrix: Optional[Dict[str, str]]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {"allowed": [], "escaped": [], "filtered": [], "replaced": []}
    for char, status in (matrix or {}).items():
        if status in groups:
            groups[status].append(char)
    return groups


def build_user_prompt(
    *,
    endpoint: str,
    param_name: str,
    location: str,
    context: str,
    char_matrix: Optional[Dict[str, str]] = None,
    snippet: str = "",
    reflected_token: str = "",
) -> str:
    data = {
        "target_endpoint": endpoint,
        "parameter_name": param_name,
        "parameter_location": location,
        "reflection_context": context,
        "character_matrix": _matrix_groups(char_matrix),
        "reflected_token": reflected_token[:120],
        "surrounding_source_snippet": (snippet or "").strip()[:1200],
    }
    return json.dumps(data, indent=2)


def _strip_code_fence(text: str) -> str:
    value = (text or "").strip()
    if value.startswith("```"):
        value = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", value)
        value = re.sub(r"\s*```$", "", value)
    return value.strip()


def parse_ai_response(raw_response: str) -> Dict[str, Any]:
    """Tolerant JSON extraction from a model response."""
    if not raw_response:
        return {"analysis": "", "payloads": []}
    cleaned = _strip_code_fence(str(raw_response))
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        cleaned = match.group(0)
    try:
        data = json.loads(cleaned)
    except Exception:
        # Some models return a bare JSON array of payloads.
        array_match = re.search(r"\[[\s\S]*\]", str(raw_response))
        if not array_match:
            return {"analysis": "", "payloads": []}
        try:
            data = json.loads(array_match.group(0))
        except Exception:
            return {"analysis": "", "payloads": []}
    if isinstance(data, list):
        return {"analysis": "", "payloads": [str(item) for item in data if str(item).strip()]}
    if not isinstance(data, dict):
        return {"analysis": "", "payloads": []}
    analysis = str(data.get("analysis") or "")
    raw_payloads = data.get("payloads") or data.get("payload") or []
    if isinstance(raw_payloads, str):
        raw_payloads = [raw_payloads]
    return {
        "analysis": analysis,
        "payloads": [str(item) for item in raw_payloads if str(item).strip()],
    }


def sanitize_payloads(
    payloads: Iterable[Any],
    *,
    limit: int = 8,
    max_length: int = 2000,
) -> List[str]:
    """Bound model output and remove duplicates/markdown artefacts."""
    result: List[str] = []
    seen = set()
    for raw in payloads:
        payload = _strip_code_fence(str(raw or ""))
        if not payload or len(payload) > max_length:
            continue
        if payload in seen:
            continue
        seen.add(payload)
        result.append(payload)
        if len(result) >= max(1, limit):
            break
    return result


@dataclass
class AIResponse:
    analysis: str = ""
    payloads: List[str] = field(default_factory=list)


class AIAnalyzer:
    """Thin async OpenRouter client with an optional injected chat transport."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_AI_MODEL,
        endpoint: str = DEFAULT_AI_ENDPOINT,
        timeout: float = DEFAULT_AI_TIMEOUT,
        console: Any = None,
        transport: Any = None,
        referer: str = "https://github.com/gl1tch0x1/xoxss",
        title: str = "XOXSS XSS Scanner",
    ):
        self.api_key = str(api_key or "").strip()
        self.model = str(model or DEFAULT_AI_MODEL)
        self.endpoint = str(endpoint or DEFAULT_AI_ENDPOINT)
        self.timeout = max(5.0, float(timeout or DEFAULT_AI_TIMEOUT))
        self.console = console
        self._transport = transport
        self.referer = referer
        self.title = title
        self._cache: Dict[str, AIResponse] = {}

    def available(self) -> bool:
        return bool(self.api_key)

    def _log(self, level: str, message: str) -> None:
        if self.console is None:
            return
        try:
            getattr(self.console, level)(message)
        except Exception:
            pass

    async def _chat(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        if self._transport is not None:
            return await self._transport(system_prompt, user_prompt)
        try:
            import aiohttp
        except Exception as exc:  # pragma: no cover - required dependency
            self._log("debug", f"AI fallback unavailable (aiohttp missing): {exc}")
            return None
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.referer,
            "X-Title": self.title,
        }
        is_reasoning = "r1" in self.model.lower() or "reasoning" in self.model.lower()
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 4000 if is_reasoning else 1200,
        }
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self.endpoint, json=body, headers=headers) as response:
                    payload = await response.text()
                    if response.status >= 400:
                        self._log(
                            "debug",
                            f"AI fallback HTTP {response.status}: {payload[:240]}",
                        )
                        return None
                    try:
                        data = json.loads(payload)
                    except Exception:
                        return payload
                    choices = data.get("choices") or []
                    if not choices:
                        return None
                    message = choices[0].get("message") or {}
                    content = message.get("content")
                    if isinstance(content, list):
                        content = "".join(
                            str(part.get("text", "")) if isinstance(part, dict) else str(part)
                            for part in content
                        )
                    return str(content or "")
        except Exception as exc:
            self._log("debug", f"AI fallback request failed: {str(exc)[:240]}")
            return None

    async def generate_payloads(
        self,
        *,
        endpoint: str,
        param_name: str,
        location: str = "GET",
        context: str = "html",
        char_matrix: Optional[Dict[str, str]] = None,
        snippet: str = "",
        reflected_token: str = "",
        limit: int = 8,
    ) -> List[str]:
        if not self.available():
            return []
        matrix_key = ",".join(f"{key}:{value}" for key, value in sorted((char_matrix or {}).items()))
        cache_key = f"{context}|{location}|{matrix_key}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            return list(cached.payloads)

        self._log(
            "debug",
            f"AI fallback: querying {self.model} for '{param_name}' [{location}] in {context}",
        )
        raw = await self._chat(
            build_system_prompt(),
            build_user_prompt(
                endpoint=endpoint,
                param_name=param_name,
                location=location,
                context=context,
                char_matrix=char_matrix,
                snippet=snippet,
                reflected_token=reflected_token,
            ),
        )
        parsed = parse_ai_response(raw or "")
        payloads = sanitize_payloads(parsed.get("payloads") or [], limit=limit)
        response = AIResponse(analysis=str(parsed.get("analysis") or ""), payloads=payloads)
        self._cache[cache_key] = response
        if response.analysis:
            self._log("debug", f"AI analysis: {response.analysis[:300]}")
        if not payloads:
            self._log("debug", "AI fallback returned no usable payloads")
        return list(payloads)


__all__ = [
    "AIAnalyzer",
    "AIResponse",
    "DEFAULT_AI_ENDPOINT",
    "DEFAULT_AI_MODEL",
    "ENV_KEYS",
    "build_system_prompt",
    "build_user_prompt",
    "parse_ai_response",
    "resolve_ai_key",
    "resolve_ai_model",
    "sanitize_payloads",
]
