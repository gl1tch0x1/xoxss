"""
GraphQL schema introspection and XSS testing module.
Discovers GraphQL endpoints and tests for XSS vulnerabilities.
"""

import re
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class GraphQLType(Enum):
    """GraphQL operation types."""
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"


@dataclass
class GraphQLField:
    """GraphQL field that may be vulnerable."""
    name: str
    field_type: str
    arguments: List[str]
    description: str


@dataclass
class GraphQLXSSVector:
    """XSS vector in GraphQL."""
    field: str
    argument: str
    operation: GraphQLType
    payload_template: str
    description: str
    confidence: float


class GraphQLAnalyzer:
    """
    GraphQL XSS analyzer.
    Performs schema introspection and tests for XSS in GraphQL endpoints.
    """

    # Common XSS-susceptible GraphQL fields
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

    # GraphQL introspection query
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

    def __init__(self):
        self._fields: List[GraphQLField] = []
        self._vectors: List[GraphQLXSSVector] = []

    def detect_graphql_endpoint(self, html_content: str) -> bool:
        """Detect if the page uses GraphQL."""
        indicators = [
            r"graphql",
            r"/graphql",
            r"apollo",
            r"relay",
            r"graphiql",
            r"\.query\s*\(",
            r"\.mutation\s*\(",
        ]

        for pattern in indicators:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True

        return False

    def extract_fields_from_schema(self, schema: Dict) -> List[GraphQLField]:
        """
        Extract fields from GraphQL schema.

        Args:
            schema: Parsed GraphQL schema

        Returns:
            List of GraphQL fields
        """
        fields = []

        types = schema.get("data", {}).get("__schema", {}).get("types", [])

        for type_obj in types:
            type_name = type_obj.get("name", "")
            if type_name.startswith("__") or type_name in ["Query", "Mutation", "Subscription"]:
                continue

            for field in type_obj.get("fields", []):
                field_name = field.get("name", "")
                field_type = field.get("type", {}).get("name", "")

                # Check if field might be XSS-susceptible
                if any(xss_field in field_name.lower() for xss_field in self.XSS_FIELDS):
                    args = [arg.get("name", "") for arg in field.get("args", [])]

                    fields.append(GraphQLField(
                        name=field_name,
                        field_type=field_type,
                        arguments=args,
                        description=field.get("description", "")
                    ))

        self._fields = fields
        return fields

    def generate_xss_vectors(
        self,
        fields: List[GraphQLField],
        marker: str
    ) -> List[GraphQLXSSVector]:
        """
        Generate XSS vectors for GraphQL fields.

        Args:
            fields: List of GraphQL fields
            marker: Unique marker

        Returns:
            List of XSS vectors
        """
        vectors = []

        for field in fields:
            # Test as query
            vectors.append(GraphQLXSSVector(
                field=field.name,
                argument=field.arguments[0] if field.arguments else "input",
                operation=GraphQLType.QUERY,
                payload_template=f'<script>{marker}</script>',
                description=f"XSS in query field {field.name}",
                confidence=0.7
            ))

            # Test as mutation
            vectors.append(GraphQLXSSVector(
                field=field.name,
                argument=field.arguments[0] if field.arguments else "input",
                operation=GraphQLType.MUTATION,
                payload_template=f'<script>{marker}</script>',
                description=f"XSS in mutation field {field.name}",
                confidence=0.8
            ))

        self._vectors = vectors
        return vectors

    def generate_test_queries(
        self,
        vectors: List[GraphQLXSSVector],
        marker: str
    ) -> List[str]:
        """
        Generate GraphQL test queries.

        Args:
            vectors: XSS vectors
            marker: Unique marker

        Returns:
            List of GraphQL queries/mutations
        """
        queries = []

        for vector in vectors:
            if vector.operation == GraphQLType.QUERY:
                query = f"""
                query {{
                    {vector.field}({vector.argument}: "{vector.payload_template.replace(marker, marker)}") {{
                        id
                    }}
                }}
                """
            elif vector.operation == GraphQLType.MUTATION:
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

    def generate_payload_with_script(
        self,
        field: str,
        argument: str,
        marker: str
    ) -> str:
        """Generate a GraphQL payload with script tag."""
        return f'<script>alert("{marker}")</script>'

    def generate_payload_with_template_literal(
        self,
        field: str,
        argument: str,
        marker: str
    ) -> str:
        """Generate a GraphQL payload with template literal."""
        return '`' + f'alert("{marker}")' + '`'
