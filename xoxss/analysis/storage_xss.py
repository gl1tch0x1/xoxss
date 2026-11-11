"""
Storage-based XSS discovery module.
Detects XSS in localStorage, sessionStorage, IndexedDB, and WebSQL.
"""

import re
from typing import List
from dataclasses import dataclass
from enum import Enum


class StorageType(Enum):
    """Browser storage types."""
    LOCALSTORAGE = "localStorage"
    SESSIONSTORAGE = "sessionStorage"
    INDEXEDDB = "indexeddb"
    WEBSQL = "websql"
    COOKIES = "cookies"


@dataclass
class StorageXSSVector:
    """XSS vector in browser storage."""
    storage_type: StorageType
    key: str
    payload_template: str
    description: str
    persistent: bool
    confidence: float


class StorageXSSAnalyzer:
    """
    Storage-based XSS analyzer.
    Detects XSS vulnerabilities in browser storage mechanisms.
    """

    # Storage access patterns
    STORAGE_PATTERNS = {
        StorageType.LOCALSTORAGE: [
            r"localStorage\.getItem\s*\(",
            r"localStorage\[",
            r"localStorage\.item\s*\(",
        ],
        StorageType.SESSIONSTORAGE: [
            r"sessionStorage\.getItem\s*\(",
            r"sessionStorage\[",
            r"sessionStorage\.item\s*\(",
        ],
        StorageType.INDEXEDDB: [
            r"indexedDB\.open\s*\(",
            r"\.add\s*\(",
            r"\.put\s*\(",
        ],
        StorageType.WEBSQL: [
            r"openDatabase\s*\(",
            r"executeSql\s*\(",
        ],
    }

    # Sink patterns for stored data
    STORAGE_SINK_PATTERNS = [
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"insertAdjacentHTML\s*\(",
        r"document\.write\s*\(",
        r"eval\s*\(",
        r"new\s+Function\s*\(",
    ]

    def __init__(self):
        self._vectors: List[StorageXSSVector] = []

    def analyze(self, js_content: str) -> List[StorageXSSVector]:
        """
        Analyze JavaScript for storage XSS vectors.

        Args:
            js_content: JavaScript source code

        Returns:
            List of XSS vectors
        """
        self._vectors = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Detect storage access
            for storage_type, patterns in self.STORAGE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if stored data reaches a sink
                        for sink_pattern in self.STORAGE_SINK_PATTERNS:
                            if re.search(sink_pattern, line, re.IGNORECASE):
                                self._vectors.append(StorageXSSVector(
                                    storage_type=storage_type,
                                    key=self._extract_key(line),
                                    payload_template="<script>alert(1)</script>",
                                    description=f"XSS via {storage_type.value} reaching {sink_pattern}",
                                    persistent=storage_type in [StorageType.LOCALSTORAGE, StorageType.INDEXEDDB, StorageType.WEBSQL],
                                    confidence=0.7
                                ))

        return self._vectors

    def _extract_key(self, line: str) -> str:
        """Extract storage key from JavaScript code."""
        # Try to extract string literal
        matches = re.findall(r'["\']([^"\']+)["\']', line)
        if matches:
            return matches[0]
        return "unknown"

    def generate_test_payloads(
        self,
        vectors: List[StorageXSSVector],
        marker: str
    ) -> List[str]:
        """Generate test payloads for storage XSS."""
        payloads = []

        for vector in vectors:
            payload = vector.payload_template.replace("alert(1)", f"alert('{marker}')")
            payloads.append(payload)

        return list(set(payloads))

    def generate_storage_injection_script(
        self,
        storage_type: StorageType,
        key: str,
        marker: str
    ) -> str:
        """Generate JavaScript to inject payload into storage."""
        if storage_type == StorageType.LOCALSTORAGE:
            return f"localStorage.setItem('{key}', '<script>alert(\"{marker}\")</script>');"
        elif storage_type == StorageType.SESSIONSTORAGE:
            return f"sessionStorage.setItem('{key}', '<script>alert(\"{marker}\")</script>');"
        elif storage_type == StorageType.INDEXEDDB:
            return f"""
            const request = indexedDB.open('test', 1);
            request.onsuccess = (e) => {{
                const db = e.target.result;
                const tx = db.transaction(['store'], 'readwrite');
                tx.objectStore('store').put({{key: '{key}', value: '<script>alert(\"{marker}\")</script>'}});
            }};
            """
        else:
            return f"localStorage.setItem('{key}', '<script>alert(\"{marker}\")</script>');"

    def detect_cookie_xss(self, js_content: str) -> bool:
        """Detect if cookies are used in XSS-susceptible contexts."""
        patterns = [
            r"document\.cookie",
            r"Cookie:\s*=",
        ]

        for pattern in patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                return True

        return False

    def get_persistent_vectors(self) -> List[StorageXSSVector]:
        """Get only persistent storage XSS vectors."""
        return [v for v in self._vectors if v.persistent]

    def get_high_confidence_vectors(self, min_confidence: float = 0.7) -> List[StorageXSSVector]:
        """Get vectors with confidence above threshold."""
        return [v for v in self._vectors if v.confidence >= min_confidence]
