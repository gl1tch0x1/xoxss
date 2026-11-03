"""
GraphQL XSS detection module.
"""

import re
import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class GraphQLInjectionType(Enum):
    """GraphQL injection types."""
    QUERY_INJECTION = "query_injection"
    VARIABLE_INJECTION = "variable_injection"
    ARGUMENT_INJECTION = "argument_injection"
    FIELD_INJECTION = "field_injection"
    FRAGMENT_INJECTION = "fragment_injection"


@dataclass
class GraphQLVulnerability:
    """GraphQL XSS vulnerability."""
    injection_type: GraphQLInjectionType
    location: str
    query: str
    payload: str
    description: str


class GraphQLAnalyzer:
    """
    Advanced GraphQL XSS analyzer.
    Detects XSS vulnerabilities in GraphQL endpoints.
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

    # Dangerous GraphQL field types
    DANGEROUS_TYPES = [
        'String',
        'HTML',
        'RichText',
        'Markup',
    ]

    def __init__(self):
        self._cache: Dict[str, List[GraphQLVulnerability]] = {}

    def detect_graphql_endpoint(self, url: str, response: str) -> bool:
        """Check if the endpoint is a GraphQL API."""
        graphql_indicators = [
            'data',
            'errors',
            'extensions',
            'query',
            'mutation',
            'subscription',
        ]

        try:
            json_data = json.loads(response)
            return any(indicator in json_data for indicator in graphql_indicators)
        except json.JSONDecodeError:
            return False

    def analyze_graphql_query(self, query: str, marker: str) -> List[GraphQLVulnerability]:
        """
        Analyze a GraphQL query for XSS vulnerabilities.

        Args:
            query: GraphQL query string
            marker: Unique marker for verification

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Check for variable injection
        variable_pattern = r'\$([a-zA-Z_]\w*)'
        variables = re.findall(variable_pattern, query)
        for var in variables:
            vulnerabilities.append(GraphQLVulnerability(
                injection_type=GraphQLInjectionType.VARIABLE_INJECTION,
                location=f"variable: ${var}",
                query=query,
                payload=f'{{"input": "<script>window.__xoxss_gql.push(\'{marker}\')</script>"}}',
                description=f"Variable ${var} can be injected with XSS payload"
            ))

        # Check for argument injection
        arg_pattern = r'([a-zA-Z_]\w*):\s*["\']([^"\']*)["\']'
        args = re.findall(arg_pattern, query)
        for arg_name, arg_value in args:
            vulnerabilities.append(GraphQLVulnerability(
                injection_type=GraphQLInjectionType.ARGUMENT_INJECTION,
                location=f"argument: {arg_name}",
                query=query,
                payload=f'{arg_name}: "<script>window.__xoxss_gql.push(\'{marker}\')</script>"',
                description=f"Argument {arg_name} can be injected with XSS payload"
            ))

        return vulnerabilities

    def generate_graphql_payload(self, injection_type: GraphQLInjectionType, marker: str) -> str:
        """Generate a GraphQL XSS payload."""
        if injection_type == GraphQLInjectionType.VARIABLE_INJECTION:
            return f'{{"input": "<script>window.__xoxss_gql.push(\'{marker}\')</script>"}}'
        elif injection_type == GraphQLInjectionType.ARGUMENT_INJECTION:
            return f'<script>window.__xoxss_gql.push(\'{marker}\')</script>'
        else:
            return f'<script>window.__xoxss_gql.push(\'{marker}\')</script>'

    def check_introspection(self, response: str) -> bool:
        """Check if GraphQL introspection is enabled."""
        try:
            json_data = json.loads(response)
            return any(intro in str(json_data) for intro in self.INTROSPECTION_QUERIES)
        except json.JSONDecodeError:
            return False

    def detect_dangerous_types(self, schema: str) -> List[str]:
        """Detect dangerous field types in GraphQL schema."""
        dangerous_types = []
        for dtype in self.DANGEROUS_TYPES:
            if dtype in schema:
                dangerous_types.append(dtype)
        return dangerous_types

    def generate_test_query(self, field_name: str, marker: str) -> str:
        """Generate a test GraphQL query for XSS testing."""
        return f'''
        query {{
            {field_name}(input: "<script>window.__xoxss_gql.push('{marker}')</script>") {{
                id
                name
            }}
        }}
        '''
