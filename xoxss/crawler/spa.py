"""
SPA-aware crawling module.
Handles hash-based routing, dynamic content loading, and client-side navigation.
"""

import re
from typing import List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class RouterType(Enum):
    """Client-side router types."""
    HISTORY_API = "history_api"
    HASH_ROUTER = "hash_router"
    CUSTOM_ROUTER = "custom_router"
    NONE = "none"


@dataclass
class SPARoute:
    """Discovered SPA route."""
    path: str
    router_type: RouterType
    framework: Optional[str] = None
    method: str = "GET"
    dynamic: bool = False


class SPACrawler:
    """
    SPA-aware crawler.
    Discovers and navigates hash-based routes and dynamic content in single-page applications.
    """

    # Router detection patterns
    ROUTER_PATTERNS = {
        RouterType.HISTORY_API: [
            r"history\.pushState\s*\(",
            r"history\.replaceState\s*\(",
            r"window\.location\.assign\s*\(",
        ],
        RouterType.HASH_ROUTER: [
            r"window\.location\.hash\s*=",
            r"window\.addEventListener\s*\(\s*[\"']hashchange[\"']",
            r"\.push\s*\(",
        ],
        RouterType.CUSTOM_ROUTER: [
            r"router\.push\s*\(",
            r"router\.navigate\s*\(",
            r"\$route\.push\s*\(",
        ],
    }

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        "React": r"React|ReactDOM|jsx|useRouter|useLocation",
        "Vue": r"Vue\.|vue-router|router\.push",
        "Angular": r"angular\.|@angular/router|Router\.navigate",
        "Svelte": r"svelte|svelte-router",
        "Next.js": r"next/router|useRouter",
        "Remix": r"remix:react-router|useNavigate",
        "Solid": r"SolidJS|createRouter",
        "Astro": r"Astro\.navigate",
    }

    def __init__(self):
        self._discovered_routes: Set[SPARoute] = set()
        self._visited_hashes: Set[str] = set()

    def detect_router_type(self, js_content: str) -> RouterType:
        """Detect the type of router used in the SPA."""
        for router_type, patterns in self.ROUTER_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    return router_type
        return RouterType.NONE

    def detect_framework(self, js_content: str) -> Optional[str]:
        """Detect which SPA framework is being used."""
        for framework, pattern in self.FRAMEWORK_PATTERNS.items():
            if re.search(pattern, js_content, re.IGNORECASE):
                return framework
        return None

    def extract_hash_routes(self, js_content: str) -> List[str]:
        """Extract hash routes from JavaScript code."""
        routes = []

        # Look for route definitions
        patterns = [
            r'path:\s*["\']([^"\']+)["\']',  # Common pattern
            r'path:\s*`([^`]+)`',               # Backtick template
            r'router\.push\s*\(\s*["\']([^"\']+)["\']',  # Vue router
            r'router\.navigate\s*\(\s*["\']([^"\']+)["\']',  # Angular router
            r"location\.hash\s*=\s*['\"]([^'\"]+)['\"]",  # Direct hash assignment
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            routes.extend(matches)

        # Clean and deduplicate
        cleaned = []
        for route in routes:
            # Remove common templating variables
            route = re.sub(r'\$\{[^}]+\}', '', route)
            route = re.sub(r':[^:]+$', '', route)  # Remove dynamic params
            if route and len(route) > 1:
                cleaned.append(route)

        return list(set(cleaned))

    def extract_api_endpoints(self, js_content: str) -> List[str]:
        """Extract API endpoints from JavaScript code."""
        endpoints = []

        patterns = [
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'ajax\s*\(\s*{\s*url:\s*["\']([^"\']+)["\']',
            r'api\.\s*\w+\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            endpoints.extend(matches)

        return list(set(endpoints))

    def discover_routes(
        self,
        js_content: str,
        html_content: str = ""
    ) -> List[SPARoute]:
        """
        Discover SPA routes from JavaScript and HTML.

        Args:
            js_content: JavaScript source code
            html_content: HTML content (optional)

        Returns:
            List of discovered SPA routes
        """
        routes = []

        framework = self.detect_framework(js_content)

        # Extract hash routes
        hash_routes = self.extract_hash_routes(js_content)
        for route in hash_routes:
            routes.append(SPARoute(
                path=route,
                router_type=RouterType.HASH_ROUTER,
                framework=framework,
                dynamic=':' in route or '<' in route
            ))

        # Extract API endpoints
        api_endpoints = self.extract_api_endpoints(js_content)
        for endpoint in api_endpoints:
            routes.append(SPARoute(
                path=endpoint,
                router_type=RouterType.CUSTOM_ROUTER,
                framework=framework,
                dynamic=':' in endpoint or '<' in endpoint
            ))

        # Look for routes in HTML (e.g., data-route attributes)
        if html_content:
            html_routes = re.findall(r'data-route\s*=\s*["\']([^"\']+)["\']', html_content)
            for route in html_routes:
                routes.append(SPARoute(
                    path=route,
                    router_type=RouterType.CUSTOM_ROUTER,
                    framework=framework,
                    dynamic=False
                ))

        self._discovered_routes.update(routes)
        return list(routes)

    def generate_test_urls(
        self,
        base_url: str,
        routes: List[SPARoute],
        marker: str
    ) -> List[str]:
        """
        Generate test URLs for discovered SPA routes.

        Args:
            base_url: Base URL of the application
            routes: List of discovered routes
            marker: Unique marker for verification

        Returns:
            List of test URLs
        """
        test_urls = []

        for route in routes:
            if route.router_type == RouterType.HASH_ROUTER:
                # Hash-based URL
                if route.path.startswith('#'):
                    url = f"{base_url}{route.path}"
                else:
                    url = f"{base_url}#{route.path}"
                test_urls.append(url)
            elif route.router_type == RouterType.CUSTOM_ROUTER:
                # API endpoint or custom route
                if route.path.startswith('/'):
                    url = f"{base_url}{route.path}"
                else:
                    url = f"{base_url}/{route.path}"
                test_urls.append(url)

        return test_urls

    def navigate_hash(
        self,
        url: str,
        marker: str
    ) -> str:
        """
        Generate a hash navigation payload.

        Args:
            url: Current URL
            marker: Unique marker

        Returns:
            JavaScript code to navigate to the hash
        """
        return f"window.location.hash = '{marker}';"
