"""
File upload XSS detection module.
"""

import re
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class FileUploadContext(Enum):
    """File upload contexts."""
    IMAGE_UPLOAD = "image_upload"
    DOCUMENT_UPLOAD = "document_upload"
    AVATAR_UPLOAD = "avatar_upload"
    PROFILE_UPLOAD = "profile_upload"
    GENERIC_UPLOAD = "generic_upload"


@dataclass
class FileUploadVulnerability:
    """File upload XSS vulnerability."""
    context: FileUploadContext
    content_type: str
    payload: str
    description: str


class FileUploadAnalyzer:
    """
    Advanced file upload XSS analyzer.
    Detects XSS vulnerabilities in file upload endpoints.
    """

    # XSS file types
    XSS_FILE_TYPES = [
        'text/html',
        'application/html',
        'image/svg+xml',
        'image/svg',
        'application/xml',
        'text/xml',
    ]

    # XSS file extensions
    XSS_EXTENSIONS = [
        '.html',
        '.htm',
        '.svg',
        '.xml',
        '.xhtml',
        '.php',
        '.asp',
        '.jsp',
    ]

    # Polyglot file extensions
    POLYGLOT_EXTENSIONS = [
        '.svg.html',
        '.html.svg',
        '.php.svg',
    ]

    # XSS payloads for file uploads
    FILE_UPLOAD_PAYLOADS = [
        '<script>alert(1)</script>',
        '<svg/onload=alert(1)>',
        '<img src=x onerror=alert(1)>',
        '<body onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ]

    def __init__(self):
        self._cache: Dict[str, List[FileUploadVulnerability]] = {}

    def detect_file_upload_endpoint(self, form_html: str) -> bool:
        """Check if the form contains a file upload input."""
        return bool(re.search(r'<input[^>]*type\s*=\s*["\']?file["\']?', form_html, re.I))

    def analyze_file_upload(
        self,
        upload_url: str,
        allowed_types: List[str],
        marker: str
    ) -> List[FileUploadVulnerability]:
        """
        Analyze file upload endpoint for XSS vulnerabilities.

        Args:
            upload_url: URL of the upload endpoint
            allowed_types: List of allowed MIME types
            marker: Unique marker for verification

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Check if dangerous file types are allowed
        for file_type in self.XSS_FILE_TYPES:
            if file_type in allowed_types:
                for payload in self.FILE_UPLOAD_PAYLOADS:
                    xss_payload = payload.replace('alert(1)', f"window.__xoxss_upload.push('{marker}')")
                    vulnerabilities.append(FileUploadVulnerability(
                        context=FileUploadContext.GENERIC_UPLOAD,
                        content_type=file_type,
                        payload=xss_payload,
                        description=f"File type {file_type} is allowed and can contain XSS"
                    ))

        # Check if SVG is allowed (SVG is particularly dangerous)
        if 'image/svg+xml' in allowed_types or 'image/svg' in allowed_types:
            svg_payload = f'<svg xmlns="http://www.w3.org/2000/svg"><script>window.__xoxss_upload.push(\'{marker}\')</script></svg>'
            vulnerabilities.append(FileUploadVulnerability(
                context=FileUploadContext.IMAGE_UPLOAD,
                content_type='image/svg+xml',
                payload=svg_payload,
                description="SVG files can execute JavaScript and are allowed"
            ))

        return vulnerabilities

    def generate_svg_payload(self, marker: str) -> str:
        """Generate an SVG XSS payload."""
        return f'<svg xmlns="http://www.w3.org/2000/svg"><script>window.__xoxss_upload.push(\'{marker}\')</script></svg>'

    def generate_polyglot_file(self, marker: str) -> str:
        """Generate a polyglot file that works as multiple types."""
        return f'''GIF89a
<script>window.__xoxss_upload.push('{marker}')</script>
'''

    def check_content_type_validation(self, response_headers: Dict[str, str]) -> bool:
        """Check if content type is validated on upload."""
        return 'content-type' in response_headers

    def check_file_extension_validation(self, allowed_extensions: List[str]) -> bool:
        """Check if file extensions are validated."""
        dangerous_extensions_present = any(
            ext in allowed_extensions for ext in self.XSS_EXTENSIONS
        )
        return not dangerous_extensions_present
