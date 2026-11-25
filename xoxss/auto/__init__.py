"""Autonomous, domain-first scanning for XOXSS.

The public entry point is :func:`xoxss.auto.engine.run_auto`.  The package is
deliberately split into small pieces so the orchestration layer stays readable:

``target``      normalise a bare domain into a safe scan URL
``plan``        build the phased, budgeted attack plan and apply its preset
``mutations``   deterministic payload mutation/evasion engine
``surface``     inventory of URLs, parameters, forms, headers and JS endpoints
``probes``      creative HTTP-level probes (redirect, host header, cache, CORS,
                JSONP, CRLF, GraphQL, static DOM/postMessage analysis)
``chains``      combine primitives into higher-impact XSS chains
``engine``      run the full autonomous workflow and merge the results
"""

from __future__ import annotations

from xoxss.auto.engine import run_auto
from xoxss.auto.mutations import Mutation, MutationEngine
from xoxss.auto.plan import AUTO_PHASES, AutoPlan, apply_auto_preset, build_plan
from xoxss.auto.target import normalize_target

__all__ = [
    "AUTO_PHASES",
    "AutoPlan",
    "Mutation",
    "MutationEngine",
    "apply_auto_preset",
    "build_plan",
    "normalize_target",
    "run_auto",
]
