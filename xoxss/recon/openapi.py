"""
OpenAPI / Swagger discovery.

When an application publishes an API description, it is a gold mine for XSS
testing: path parameters, query parameters, JSON body fields and content types
are all enumerated for us.  This module finds common spec locations and turns
the document into concrete request templates.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

class HttpLike(Protocol):  # pragma: no cover
    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> Any: ...


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = False) -> None: ...
    def debug(self, message: str) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...


SPEC_PATHS: Tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api-docs",
    "/api-docs/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger-resources",
    "/.well-known/openapi.json",
)

PLACEHOLDER = "xoxss"


@dataclass
class APIParameter:
    name: str
    location: str = "query"
    required: bool = False
    example: str = PLACEHOLDER
    schema_type: str = "string"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "required": self.required,
            "example": self.example,
            "type": self.schema_type,
        }


@dataclass
class APIOperation:
    url: str
    method: str = "GET"
    parameters: List[APIParameter] = field(default_factory=list)
    content_type: str = ""
    sample_body: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    operation_id: str = ""

    def query_names(self) -> List[str]:
        return [param.name for param in self.parameters if param.location == "query"]

    def body_names(self) -> List[str]:
        return [param.name for param in self.parameters if param.location in ("body", "formData")]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": [param.to_dict() for param in self.parameters],
            "content_type": self.content_type,
            "sample_body": self.sample_body,
            "source": self.source,
            "operation_id": self.operation_id,
        }


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _example_for(schema: Dict[str, Any]) -> str:
    if not isinstance(schema, dict):
        return PLACEHOLDER
    if "example" in schema:
        return str(schema["example"])
    if "default" in schema:
        return str(schema["default"])
    if "enum" in schema and schema["enum"]:
        return str(schema["enum"][0])
    kind = str(schema.get("type") or "string")
    if kind in ("integer", "number"):
        return "1"
    if kind == "boolean":
        return "true"
    return PLACEHOLDER


def _params_from_schema(schema: Dict[str, Any], location: str, required: bool = False) -> List[APIParameter]:
    params: List[APIParameter] = []
    if not isinstance(schema, dict):
        return params
    properties = schema.get("properties")
    if isinstance(properties, dict):
        required_names = set(schema.get("required") or [])
        for name, spec in properties.items():
            spec = spec if isinstance(spec, dict) else {}
            params.append(
                APIParameter(
                    name=str(name),
                    location=location,
                    required=str(name) in required_names,
                    example=_example_for(spec),
                    schema_type=str(spec.get("type") or "string"),
                )
            )
    return params


def _resolve_ref(document: Dict[str, Any], ref: str) -> Dict[str, Any]:
    if not ref.startswith("#/"):
        return {}
    node: Any = document
    for chunk in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(chunk)
    return node if isinstance(node, dict) else {}


def _body_from_request_body(document: Dict[str, Any], request_body: Dict[str, Any]) -> Tuple[str, Dict[str, Any], List[APIParameter]]:
    content = request_body.get("content") if isinstance(request_body, dict) else None
    if not isinstance(content, dict):
        return "", {}, []
    for content_type, media in content.items():
        if not isinstance(media, dict):
            continue
        schema = media.get("schema") or {}
        if isinstance(schema, dict) and "$ref" in schema:
            schema = _resolve_ref(document, str(schema["$ref"]))
        elif isinstance(schema, dict) and schema.get("type") == "array":
            schema = schema.get("items") or {}
        params = _params_from_schema(schema, "body")
        sample = {param.name: param.example for param in params}
        return str(content_type), sample, params
    return "", {}, []


def parse_openapi(document: Dict[str, Any], spec_url: str) -> List[APIOperation]:
    """Turn an OpenAPI 2/3 document into request templates."""
    if not isinstance(document, dict):
        return []
    base = _origin(spec_url)
    servers = document.get("servers") or []
    has_server = False
    if isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict) and server.get("url"):
                base = urljoin(base + "/", str(server["url"]))
                has_server = True
                break
    # Swagger 2 describes the API host and scheme at the document root.
    host = str(document.get("host") or "")
    if host and not has_server:
        schemes = document.get("schemes") or []
        scheme = (
            str(schemes[0])
            if isinstance(schemes, list) and schemes
            else (urlsplit(spec_url).scheme or "https")
        )
        base = f"{scheme}://{host}"
    base_path = str(document.get("basePath") or "")
    paths = document.get("paths") or {}
    if not isinstance(paths, dict):
        return []
    operations: List[APIOperation] = []
    methods = ("get", "post", "put", "patch", "delete", "options", "head")

    for path, node in paths.items():
        if not isinstance(node, dict):
            continue
        shared_params = node.get("parameters") or []
        for method in methods:
            operation = node.get(method)
            if not isinstance(operation, dict):
                continue
            params: List[APIParameter] = []
            for raw in [*shared_params, *(operation.get("parameters") or [])]:
                if not isinstance(raw, dict):
                    continue
                if "$ref" in raw:
                    raw = _resolve_ref(document, str(raw["$ref"]))
                name = str(raw.get("name") or "").strip()
                location = str(raw.get("in") or "query")
                if not name:
                    continue
                schema = raw.get("schema") or {}
                if isinstance(schema, dict) and "$ref" in schema:
                    schema = _resolve_ref(document, str(schema["$ref"]))
                # Swagger 2 describes non-body parameters inline (type/default on
                # the parameter itself) instead of under a ``schema`` object.
                if not schema and location != "body":
                    schema = raw
                if location == "body":
                    if isinstance(schema, dict) and schema.get("type") == "array":
                        schema = schema.get("items") or {}
                    expanded = _params_from_schema(schema, "body")
                    if expanded:
                        params.extend(expanded)
                    else:
                        params.append(
                            APIParameter(
                                name=name,
                                location="body",
                                required=bool(raw.get("required")),
                                example=_example_for(schema if isinstance(schema, dict) else {}),
                                schema_type="string",
                            )
                        )
                    continue
                params.append(
                    APIParameter(
                        name=name,
                        location=location,
                        required=bool(raw.get("required")),
                        example=_example_for(schema if isinstance(schema, dict) else {}),
                        schema_type=str((schema or {}).get("type") or "string")
                        if isinstance(schema, dict)
                        else "string",
                    )
                )

            content_type = ""
            consumes = operation.get("consumes") or document.get("consumes") or []
            if isinstance(consumes, list) and consumes:
                content_type = str(consumes[0])
            sample_body: Dict[str, Any] = {
                param.name: param.example
                for param in params
                if param.location == "body"
            }
            form_sample = {
                param.name: param.example
                for param in params
                if param.location == "formData"
            }
            if form_sample and not sample_body:
                sample_body = form_sample
            if isinstance(operation.get("requestBody"), dict):
                content_type, request_sample, body_params = _body_from_request_body(
                    document, operation["requestBody"]
                )
                params.extend(body_params)
                sample_body.update(request_sample)

            resolved_path = path
            for param in params:
                if param.location == "path":
                    resolved_path = resolved_path.replace(
                        "{" + param.name + "}", quote(param.example, safe="")
                    )
            suffix = "/".join(
                part.strip("/")
                for part in (base_path, resolved_path)
                if part.strip("/")
            )
            url = urljoin(base.rstrip("/") + "/", suffix)
            query = [
                (param.name, param.example)
                for param in params
                if param.location == "query"
            ]
            if query:
                url = url + ("&" if "?" in url else "?") + urlencode(query)

            operations.append(
                APIOperation(
                    url=url,
                    method=method.upper(),
                    parameters=params,
                    content_type=content_type,
                    sample_body=sample_body,
                    source=spec_url,
                    operation_id=str(operation.get("operationId") or ""),
                )
            )
    return operations


def _maybe_yaml(text: str) -> Optional[Dict[str, Any]]:
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    try:
        payload = yaml.safe_load(text)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def parse_spec_text(text: str, spec_url: str) -> List[APIOperation]:
    text = (text or "").strip()
    if not text:
        return []
    if len(text) > 8_000_000:
        # A fetched "spec" this large is either a bombed YAML (alias
        # expansion) or a giant phishing page; parsing it is wasted risk.
        return []
    document: Optional[Dict[str, Any]] = None
    if text.startswith("{"):
        try:
            document = json.loads(text)
        except Exception:
            document = None
    if document is None:
        document = _maybe_yaml(text)
    if not isinstance(document, dict):
        return []
    if "swagger" not in document and "openapi" not in document:
        return []
    return parse_openapi(document, spec_url)


class OpenAPIFinder:
    """Probe common spec locations and collect API request templates."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        paths: Optional[Sequence[str]] = None,
        timeout: float = 15.0,
        max_operations: int = 500,
    ):
        self.http = http
        self.console = console
        self.paths = list(paths or SPEC_PATHS)
        self.timeout = max(3.0, timeout)
        self.max_operations = max(1, max_operations)

    async def _probe(self, url: str) -> List[APIOperation]:
        try:
            response = await asyncio.wait_for(self.http.get(url, cache=True), timeout=self.timeout)
        except Exception:
            return []
        if getattr(response, "error", None) or not getattr(response, "text", ""):
            return []
        content_type = ""
        try:
            content_type = response.header("content-type")
        except Exception:
            pass
        if "html" in content_type.lower() and "<html" in response.text[:500].lower():
            return []
        return parse_spec_text(response.text, url)

    async def discover(self, target: str) -> List[APIOperation]:
        origin = _origin(target)
        candidates = [urljoin(origin + "/", path.lstrip("/")) for path in self.paths]
        results = await asyncio.gather(*(self._probe(url) for url in candidates))
        operations: List[APIOperation] = []
        seen: set = set()
        for group in results:
            for operation in group:
                key = (operation.method, operation.url.split("?")[0])
                if key in seen:
                    continue
                seen.add(key)
                operations.append(operation)
                if len(operations) >= self.max_operations:
                    break
            if len(operations) >= self.max_operations:
                break
        if operations:
            self.console.info(
                f"OpenAPI: {len(operations)} operation(s) discovered", important=False
            )
        return operations


__all__ = [
    "APIParameter",
    "APIOperation",
    "SPEC_PATHS",
    "OpenAPIFinder",
    "parse_openapi",
    "parse_spec_text",
]
