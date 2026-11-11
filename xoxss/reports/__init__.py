"""Independent renderers for XOXSS report formats."""

from xoxss.reports.html import write_html_report
from xoxss.reports.json import report_payload, write_json_report
from xoxss.reports.markdown import write_markdown_report
from xoxss.reports.sarif import build_sarif_document, write_sarif_file

__all__ = [
    "report_payload",
    "write_json_report",
    "write_markdown_report",
    "write_html_report",
    "build_sarif_document",
    "write_sarif_file",
]
