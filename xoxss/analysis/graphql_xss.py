"""
GraphQL schema introspection and XSS testing module (compatibility shim).

Canonical implementation has been unified into :mod:`xoxss.analysis.graphql`.
"""

from __future__ import annotations

from xoxss.analysis.graphql import (
    GraphQLAnalyzer,
    GraphQLField,
    GraphQLInjectionType,
    GraphQLType,
    GraphQLVulnerability,
    GraphQLXSSVector,
)

__all__ = [
    "GraphQLAnalyzer",
    "GraphQLField",
    "GraphQLInjectionType",
    "GraphQLType",
    "GraphQLVulnerability",
    "GraphQLXSSVector",
]
