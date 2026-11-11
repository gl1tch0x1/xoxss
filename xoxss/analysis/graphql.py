"""
GraphQL schema introspection, endpoint detection, and XSS testing module.
Consolidates GraphQL endpoint fingerprinting, introspection analysis, and injection vector generation.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class GraphQLInjectionType(Enum):
    """GraphQL injection types."""
    QUERY_INJECTION = "query_injection"
    VARIABLE_INJECTION = "variable_injection"
    ARGUMENT_INJECTION = "argument_injection"
    FIELD_INJECTION = "field_injection"
    FRAGMENT_INJECTION = "fragment_injection"


class GraphQLType(Enum):
    """GraphQL operation types."""
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"


@dataclass
class GraphQLField:
    """GraphQL field that may be susceptible to XSS."""
    name: str
    field_type: str = ""
    arguments: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class GraphQLXSSVector:
    """XSS vector in GraphQL."""
    field: str
    argument: str
    operation: GraphQLType
    payload_template: str
    description: str
    confidence: float = 0.7


@dataclass
class GraphQLVulnerability:
    """GraphQL XSS vulnerability finding."""
    injection_type: GraphQLInjectionType
    location: str
    query: str
    payload: str
    description: str


class GraphQLAnalyzer:
    """
    Comprehensive GraphQL XSS analyzer.
    Detects GraphQL endpoints, checks introspection status, analyzes schema fields,
    and generates targeted XSS vectors.
    """

    # GraphQL injection patterns
    INJECTION_PATTERNS = {
        GraphQLInjectionType.QUERY_INJECTION: [
            r'query\s*\{[^}]*\{[^}]*\}[^}]*\}',
            r'mutation\s*\{[^}]*\{[^}]*\}[^}]*\}',
        ],
        GraphQLInjectionType.VARIABLE_INJECTION: [
            r'\$[a-zA-Z_]\w*:\s*[A-Z]',
        ],
        GraphQLInjectionType.ARGUMENT_INJECTION: [
            r'\([a-zA-Z_]\w*:\s*["\'][^"\']*["\']\)',
        ],
    }

    # Common GraphQL introspection queries
    INTROSPECTION_QUERIES = [
        '__schema',
        '__type',
        '__typename',
    ]

    # Full GraphQL introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                description
                fields(includeDeprecated: true) {
                    name
                    type {
                        name
                        kind
                    }
                    args {
                        name
                        type {
                            name
                            kind
                        }
                    }
                }
            }
        }
    }
    """

    # Common XSS-susceptible GraphQL field names
    XSS_FIELDS = [
        "description",
        "bio",
        "content",
        "comment",
        "message",
        "summary",
        "text",
        "html",
        "markup",
        "body",
    ]

    # Dangerous GraphQL field types
    DANGEROUS_TYPES = [
        'String',
        'HTML',
        'RichText',
        'Markup',
    ]

    def __init__(self) -> None:
        self._cache: Dict[str, List[GraphQLVulnerability]] = {}
        self._fields: List[GraphQLField] = []
        self._vectors: List[GraphQLXSSVector] = []

    def detect_graphql_endpoint(self, url_or_html: str, response: Optional[str] = None) -> bool:
        """
        Check if an endpoint or HTML page uses a GraphQL API.
        Accepts either (url, response_json_string) or a single HTML/source string.
        """
        if response is not None:
            # JSON response fingerprinting
            try:
                json_data = json.loads(response)
            except (json.JSONDecodeError, ValueError, TypeError):
                return False
            if not isinstance(json_data, dict):
                return False

            raw = str(json_data)
            if "__typename" in raw or "__schema" in raw:
                return True
            has_data = "data" in json_data
            has_gql_siblings = ("errors" in json_data) or ("extensions" in json_data)
            return has_data and has_gql_siblings

        # HTML/source content matching
        html_content = url_or_html or ""
        indicators = [
            r"graphql",
            r"/graphql",
            r"apollo",
            r"relay",
            r"graphiql",
            r"\.query\s*\(",
            r"\.mutation\s*\(",
        ]
        return any(re.search(pat, html_content, re.IGNORECASE) for pat in indicators)

    def check_introspection(self, response: str) -> bool:
        """Check if GraphQL introspection is enabled."""
        try:
            json_data = json.loads(response)
        except (json.JSONDecodeError, ValueError, TypeError):
            return False
        raw = str(json_data)
        return "__schema" in raw or "__type(name:" in raw or "__typename!" in raw

    def detect_dangerous_types(self, schema: str) -> List[str]:
        """Detect dangerous field types in GraphQL schema."""
        dangerous_types = []
        for dtype in self.DANGEROUS_TYPES:
            if dtype in schema:
                dangerous_types.append(dtype)
        return dangerous_types

    def extract_fields_from_schema(self, schema: Dict[str, Any]) -> List[GraphQLField]:
        """Extract fields from a parsed GraphQL schema dictionary."""
        fields: List[GraphQLField] = []
        types = schema.get("data", {}).get("__schema", {}).get("types", [])

        for type_obj in types:
            type_name = type_obj.get("name", "")
            if type_name.startswith("__") or type_name in ["Query", "Mutation", "Subscription"]:
                continue

            for field_data in type_obj.get("fields", []) or []:
                field_name = field_data.get("name", "")
                field_type = field_data.get("type", {}).get("name", "")

                if any(xss_field in field_name.lower() for xss_field in self.XSS_FIELDS):
                    args = [arg.get("name", "") for arg in field_data.get("args", []) if arg.get("name")]
                    fields.append(
                        GraphQLField(
                            name=field_name,
                            field_type=field_type or "",
                            arguments=args,
                            description=field_data.get("description", "") or "",
                        )
                    )

        self._fields = fields
        return fields

    def generate_xss_vectors(
        self,
        fields: List[GraphQLField],
        marker: str,
    ) -> List[GraphQLXSSVector]:
        """Generate XSS vectors for GraphQL fields."""
        vectors: List[GraphQLXSSVector] = []
        for f in fields:
            arg = f.arguments[0] if f.arguments else "input"
            vectors.append(
                GraphQLXSSVector(
                    field=f.name,
                    argument=arg,
                    operation=GraphQLType.QUERY,
                    payload_template=f'<script>{marker}</script>',
                    description=f"XSS in query field {f.name}",
                    confidence=0.7,
                )
            )
            vectors.append(
                GraphQLXSSVector(
                    field=f.name,
                    argument=arg,
                    operation=GraphQLType.MUTATION,
                    payload_template=f'<script>{marker}</script>',
                    description=f"XSS in mutation field {f.name}",
                    confidence=0.8,
                )
            )
        self._vectors = vectors
        return vectors

    def generate_test_queries(
        self,
        vectors: List[GraphQLXSSVector],
        marker: str,
    ) -> List[str]:
        """Generate GraphQL test queries from vectors."""
        queries: List[str] = []
        for vector in vectors:
            if vector.operation == GraphQLType.QUERY:
                query = f"""
                query {{
                    {vector.field}({vector.argument}: "{vector.payload_template.replace(marker, marker)}") {{
                        id
                    }}
                }}
                """
            else:
                query = f"""
                mutation {{
                    {vector.field}({vector.argument}: "{vector.payload_template.replace(marker, marker)}") {{
                        id
                    }}
                }}
                """
            queries.append(query.strip())
        return queries

    def test_inline_fragment_xss(self, marker: str) -> str:
        """Test inline fragment XSS."""
        return f"""
        query {{
            __typename
            ... on {{__typename "{marker}"}}
        }}
        """

    def test_subscription_xss(self, marker: str) -> str:
        """Test subscription XSS."""
        return f"""
        subscription {{
            messageUpdated(channel: "{marker}") {{
                content
            }}
        }}
        """

    def generate_test_query(self, field_name: str, marker: str) -> str:
        """Generate a test GraphQL query for XSS testing."""
        return f"""
        query {{
            {field_name}(input: "<script>window.__xoxss_gql.push('{marker}')</script>") {{
                id
                name
            }}
        }}
        """

    def analyze_graphql_query(self, query: str, marker: str) -> List[GraphQLVulnerability]:
        """Analyze a GraphQL query string for injection points."""
        vulnerabilities: List[GraphQLVulnerability] = []

        # Check for variable injection
        variable_pattern = r'\$([a-zA-Z_]\w*)'
        for var in re.findall(variable_pattern, query):
            vulnerabilities.append(
                GraphQLVulnerability(
                    injection_type=GraphQLInjectionType.VARIABLE_INJECTION,
                    location=f"variable: ${var}",
                    query=query,
                    payload=f'{{"input": "<script>window.__xoxss_gql.push(\'{marker}\')</script>"}}',
                    description=f"Variable ${var} can be injected with XSS payload",
                )
            )

        # Check for argument injection
        arg_pattern = r'([a-zA-Z_]\w*):\s*["\']([^"\']*)["\']'
        for arg_name, _ in re.findall(arg_pattern, query):
            vulnerabilities.append(
                GraphQLVulnerability(
                    injection_type=GraphQLInjectionType.ARGUMENT_INJECTION,
                    location=f"argument: {arg_name}",
                    query=query,
                    payload=f'{arg_name}: "<script>window.__xoxss_gql.push(\'{marker}\')</script>"',
                    description=f"Argument {arg_name} can be injected with XSS payload",
                )
            )

        return vulnerabilities

    def generate_graphql_payload(self, injection_type: GraphQLInjectionType, marker: str) -> str:
        """Generate a GraphQL XSS payload."""
        if injection_type == GraphQLInjectionType.VARIABLE_INJECTION:
            return f'{{"input": "<script>window.__xoxss_gql.push(\'{marker}\')</script>"}}'
        return f'<script>window.__xoxss_gql.push(\'{marker}\')</script>'

    def generate_payload_with_script(self, field: str, argument: str, marker: str) -> str:
        """Generate a GraphQL payload with script tag."""
        return f'<script>alert("{marker}")</script>'

    def generate_payload_with_template_literal(self, field: str, argument: str, marker: str) -> str:
        """Generate a GraphQL payload with template literal."""
        return f'`alert("{marker}")`'


__all__ = [
    "GraphQLInjectionType",
    "GraphQLType",
    "GraphQLField",
    "GraphQLXSSVector",
    "GraphQLVulnerability",
    "GraphQLAnalyzer",
]
