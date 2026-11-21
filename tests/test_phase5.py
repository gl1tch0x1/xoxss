"""Tests for Phase 5 professional features: CWE/CVSS, compliance, collaboration."""

from __future__ import annotations

import json
from types import SimpleNamespace


from xoxss.core.compliance import (
    compliance_for_kind,
    cwe_for_kind,
    cvss_base_score,
    cvss_for_finding,
    cvss_vector,
    finding_dedupe_fingerprint,
    owasp_id_for_kind,
    secondary_cwes,
)
from xoxss.reports.collaboration import collaboration_bundle, VALID_STATUSES
from xoxss.reports.compliance import compliance_records, compliance_summary
from xoxss.reports.sarif import build_sarif_document


def _finding(kind="Reflected XSS", **kw):
    base = dict(
        kind=kind,
        url="https://target.example/search?q=x",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        confidence="high",
        evidence="payload reflected",
        finding_id="",
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestCweMapping:
    def test_xss_families_map_to_cwe79(self):
        for kind in (
            "Reflected XSS",
            "DOM XSS",
            "DOM XSS (taint flow)",
            "Stored XSS",
            "Blind XSS",
            "Cookie XSS",
            "Header XSS",
            "WebSocket XSS",
        ):
            assert cwe_for_kind(kind) == "CWE-79", kind

    def test_non_xss_families(self):
        assert cwe_for_kind("CRLF Injection") == "CWE-113"
        assert cwe_for_kind("Open Redirect") == "CWE-601"
        assert cwe_for_kind("Prototype Pollution") == "CWE-1321"
        assert cwe_for_kind("CORS Misconfiguration") == "CWE-942"

    def test_unknown_defaults_to_cwe79(self):
        assert cwe_for_kind("Some New Vector") == "CWE-79"

    def test_secondary_cwes(self):
        assert "CWE-116" in secondary_cwes("Reflected XSS")
        assert "CWE-200" in secondary_cwes("Blind XSS")
        assert secondary_cwes("CORS Misconfiguration") == []


class TestCvss:
    def test_vector_format(self):
        v = cvss_vector("Reflected XSS", "high")
        assert v.startswith("CVSS:3.1/AV:N/")
        assert "/UI:R/" in v

    def test_stored_widens_scope(self):
        stored = cvss_vector("Stored XSS", "confirmed", stored=True)
        assert "/S:C/" in stored or "/PR:L/" in stored

    def test_known_vector_scores(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H = 10.0
        assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
        # All impacts none -> 0.0
        assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N") == 0.0

    def test_score_range(self):
        for conf in ("confirmed", "high", "medium", "low"):
            result = cvss_for_finding(_finding(confidence=conf))
            assert 0.0 <= result["baseScore"] <= 10.0
            assert result["severity"] in ("critical", "high", "medium", "low")
            assert "vector" in result and result["vector"].startswith("CVSS:3.1/")

    def test_higher_confidence_scores_higher(self):
        high = cvss_for_finding(_finding(confidence="high"))["baseScore"]
        low = cvss_for_finding(_finding(confidence="low"))["baseScore"]
        assert high > low


class TestComplianceMapping:
    def test_owasp_mapping(self):
        assert owasp_id_for_kind("Reflected XSS") == "A03:2021"
        assert owasp_id_for_kind("CRLF Injection") == "A05:2021"
        assert owasp_id_for_kind("Open Redirect") == "A01:2021"

    def test_frameworks_present(self):
        comp = compliance_for_kind("Reflected XSS")
        assert set(comp) == {"owasp", "pci_dss", "hipaa"}
        assert comp["pci_dss"]["id"] == "6.2.4"
        assert "164.312" in comp["hipaa"]["id"]

    def test_fingerprint_stable(self):
        f = _finding()
        assert finding_dedupe_fingerprint(f) == finding_dedupe_fingerprint(f)
        f2 = _finding(url="https://target.example/other?x=1")
        assert finding_dedupe_fingerprint(f) != finding_dedupe_fingerprint(f2)


class _FakeScanner:
    def __init__(self, findings):
        self.findings = findings
        self.target = "https://target.example"
        self.waf = SimpleNamespace(names=[], blocking=False)
        self.stats = SimpleNamespace(elapsed=1.0, truncated_responses=0)
        self.endpoints = set()
        self.blind_markers = []


class TestSarifDeep:
    def test_sarif_has_cwe_and_cvss(self):
        doc = build_sarif_document(
            [_finding()], target="https://target.example"
        )
        run = doc["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["properties"]["cwe"] == "CWE-79"
        assert "external/cwe/cwe79" in rule["properties"]["tags"]
        assert "security-severity" in rule["properties"]
        result_props = run["results"][0]["properties"]
        assert result_props["cwe"] == "CWE-79"
        assert result_props["cvss"]["vector"].startswith("CVSS:3.1/")
        assert "compliance" in result_props
        assert "dedupeFingerprint" in result_props

    def test_sarif_roundtrip_json(self):
        doc = build_sarif_document([_finding()], target="https://t.example")
        parsed = json.loads(json.dumps(doc))
        assert parsed["version"] == "2.1.0"
        assert parsed["runs"][0]["results"]


class TestComplianceReport:
    def test_records_have_frameworks(self):
        scanner = _FakeScanner([_finding(), _finding(kind="CRLF Injection", parameter="x")])
        records = compliance_records(scanner)
        assert len(records) == 2
        xss = records[0]
        assert xss["cwe"] == "CWE-79"
        assert xss["cvss"]["baseScore"] > 0
        assert xss["frameworks"]["owasp"]["id"] == "A03:2021"

    def test_summary_buckets_controls(self):
        scanner = _FakeScanner([_finding(), _finding(kind="CRLF Injection")])
        summary = compliance_summary(scanner)
        assert summary["totals"]["findings"] == 2
        assert summary["frameworks"]["owasp_top10_2021"]
        assert summary["frameworks"]["pci_dss_4_0"]
        assert summary["frameworks"]["hipaa_security_rule"]

    def test_write_compliance_report(self, tmp_path):
        from xoxss.reports.compliance import write_compliance_report

        scanner = _FakeScanner([_finding()])
        path = tmp_path / "comp.json"
        write_compliance_report(path, scanner)
        data = json.loads(path.read_text())
        assert data["totals"]["findings"] == 1


class TestCollaboration:
    def test_bundle_dedupes(self):
        scanner = _FakeScanner([_finding(), _finding(payload="<svg onload=1>")])
        bundle = collaboration_bundle(scanner)
        assert bundle["counts"]["rawFindings"] == 2
        assert bundle["counts"]["uniqueIssues"] == 1
        assert bundle["issues"][0]["occurrences"] == 2

    def test_status_fields(self):
        scanner = _FakeScanner(
            [_finding(status="triaged", assigned_to="alice", notes="checking")]
        )
        bundle = collaboration_bundle(scanner)
        issue = bundle["issues"][0]
        assert issue["status"] == "triaged"
        assert issue["assignedTo"] == "alice"
        assert issue["notes"] == "checking"

    def test_valid_statuses(self):
        assert "false_positive" in VALID_STATUSES
        assert "accepted_risk" in VALID_STATUSES

    def test_write_collab_report(self, tmp_path):
        from xoxss.reports.collaboration import write_collaboration_report

        scanner = _FakeScanner([_finding()])
        path = tmp_path / "collab.json"
        write_collaboration_report(path, scanner)
        data = json.loads(path.read_text())
        assert data["schemaVersion"] == 1
        assert data["issues"]


class TestFindingTriageFields:
    def test_finding_defaults(self):
        from xoxss.core.finding import Finding

        f = Finding(kind="Reflected XSS", url="https://t.example", parameter="q", method="GET", payload="x")
        assert f.status == "open"
        assert f.assigned_to == ""
        assert f.notes == ""
        d = f.to_dict()
        assert d["status"] == "open"
