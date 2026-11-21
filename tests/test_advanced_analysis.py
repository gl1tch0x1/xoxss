"""
Tests for advanced XSS analysis modules.

Tests for:
- Template Injection Detection
- Mutation XSS (mXSS) Detection
- HTTP Parameter Pollution (HPP)
- Cookie-based XSS
- Web Components XSS
- WASM XSS
- Clipboard XSS
"""


from xoxss.analysis.template_injection import (
    Framework,
    TemplateInjectionDetector,
    TemplateVulnerability,
)
from xoxss.analysis.mxss import MXSSDetector, MXSSAnalysis, SanitizerType
from xoxss.analysis.hpp import HPPDetector, HPPVulnerability
from xoxss.analysis.cookie_xss import CookieXSSDetector, CookieSink, CookieXSSVulnerability
from xoxss.analysis.web_components import (
    ComponentType,
    WebComponentDetector,
    WebComponentVulnerability,
)
from xoxss.analysis.wasm_xss import WASMXSSDetector, WASMSink, WASMXSSVulnerability
from xoxss.analysis.clipboard_xss import (
    ClipboardSink,
    ClipboardXSSDetector,
    ClipboardXSSVulnerability,
)


class TestTemplateInjection:
    """Test template injection detection."""

    def test_detects_angular(self):
        detector = TemplateInjectionDetector()
        html = '<div ng-app="myApp">{{ user.name }}</div>'
        detected = detector.detect_frameworks(html)
        assert Framework.ANGULAR in detected

    def test_detects_vue(self):
        detector = TemplateInjectionDetector()
        html = '<div id="app" v-app>{{ message }}</div>'
        js = 'Vue.component("app", {})'
        detected = detector.detect_frameworks(html, js)
        assert Framework.VUE in detected

    def test_detects_svelte(self):
        detector = TemplateInjectionDetector()
        html = '<div>{@html content}</div>'
        detected = detector.detect_frameworks(html)
        assert Framework.SVELTE in detected

    def test_detects_alpine(self):
        detector = TemplateInjectionDetector()
        html = '<div x-data="{ count: 0 }" x-html="content"></div>'
        detected = detector.detect_frameworks(html)
        assert Framework.ALPINE in detected

    def test_generates_angular_payloads(self):
        detector = TemplateInjectionDetector()
        payloads = detector.generate_payloads(Framework.ANGULAR, "marker")
        assert len(payloads) > 0
        assert any("marker" in p for p in payloads)

    def test_generates_vue_payloads(self):
        detector = TemplateInjectionDetector()
        payloads = detector.generate_payloads(Framework.VUE, "marker")
        assert len(payloads) > 0
        assert any("marker" in p for p in payloads)

    def test_test_injection_point_returns_vulnerability(self):
        detector = TemplateInjectionDetector()
        vuln = detector.test_injection_point("input", Framework.ANGULAR, "marker")
        assert vuln is not None
        assert vuln.framework == Framework.ANGULAR
        assert vuln.injection_point == "input"

    def test_scan_returns_vulnerabilities(self):
        detector = TemplateInjectionDetector()
        html = '<div ng-app="myApp">{{ user.name }}</div>'
        vulns = detector.scan_for_template_injection(html, injection_points=["input"])
        assert len(vulns) > 0

    def test_assess_risk_critical(self):
        detector = TemplateInjectionDetector()
        vulns = [
            TemplateVulnerability(
                framework=Framework.ANGULAR,
                injection_point="input",
                context="test",
                payload="<script>alert(1)</script>",
                severity="high",
                confidence=0.9,
            )
        ]
        risk = detector.assess_risk(vulns)
        assert risk == "critical"

    def test_assess_risk_none(self):
        detector = TemplateInjectionDetector()
        risk = detector.assess_risk([])
        assert risk == "none"


class TestMXSSDetection:
    """Test mutation XSS detection."""

    def test_detects_dompurify(self):
        detector = MXSSDetector()
        js = "DOMPurify version 2.0.17"
        analysis = detector.detect_mutation_xss(js)
        assert analysis.sanitizer == SanitizerType.DOMPURIFY
        assert analysis.version == "2.0.17"

    def test_detects_vulnerable_version(self):
        detector = MXSSDetector()
        js = "DOMPurify version 2.0.17"
        analysis = detector.detect_mutation_xss(js)
        assert analysis.vulnerable is True
        assert analysis.has_mutation_xss is True

    def test_detects_svg_context(self):
        detector = MXSSDetector()
        js = "const svg = document.createElement('svg')"
        analysis = detector.detect_mutation_xss(js)
        assert "svg" in analysis.contexts

    def test_generates_svg_payloads(self):
        detector = MXSSDetector()
        analysis = MXSSAnalysis(
            has_mutation_xss=True,
            sanitizer=None,
            version=None,
            vulnerable=False,
            contexts=["svg"],
            cve_ids=[],
        )
        payloads = detector.generate_test_payloads(analysis, "marker")
        assert len(payloads) > 0
        assert any("svg" in p.lower() for p in payloads)

    def test_check_html_sanitizer_usage(self):
        detector = MXSSDetector()
        js = "DOMPurify version 2.0.17; DOMPurify.sanitize(input)"
        assert detector.check_html_sanitizer_usage(js) is True

    def test_get_sanitizer_recommendation(self):
        detector = MXSSDetector()
        analysis = MXSSAnalysis(
            has_mutation_xss=True,
            sanitizer=SanitizerType.DOMPURIFY,
            version="2.0.17",
            vulnerable=True,
            contexts=[],
            cve_ids=["CVE-2019-16770"],
        )
        rec = detector.get_sanitizer_recommendation(analysis)
        assert "upgrade" in rec.lower()


class TestHPPDetection:
    """Test HTTP parameter pollution detection."""

    def test_parse_parameters(self):
        detector = HPPDetector()
        url = "https://example.com?param1=value1&param2=value2"
        params = detector.parse_parameters(url)
        assert "param1" in params
        assert "param2" in params

    def test_detects_duplicate_parameters(self):
        detector = HPPDetector()
        url = "https://example.com?param=value1&param=value2"
        duplicates = detector.detect_duplicate_parameters(url)
        assert "param" in duplicates

    def test_generates_hpp_variants(self):
        detector = HPPDetector()
        url = "https://example.com?param=value"
        variants = detector.generate_hpp_variants(url, "param", "<script>alert(1)</script>", "marker")
        assert len(variants) > 0

    def test_test_waf_bypass_via_hpp(self):
        detector = HPPDetector()
        url = "https://example.com?param=value1&param=value2"
        bypass = detector.test_waf_bypass_via_hpp(url, "param")
        assert bypass is True

    def test_scan_returns_vulnerabilities(self):
        detector = HPPDetector()
        url = "https://example.com?redirect=/home&redirect=/evil"
        vulns = detector.scan_for_hpp_vulnerabilities(url)
        assert len(vulns) > 0

    def test_assess_hpp_risk_critical(self):
        detector = HPPDetector()
        vulns = [
            HPPVulnerability(
                parameter="redirect",
                pollution_type="duplicate",
                payload="<script>alert(1)</script>",
                url="https://example.com",
                severity="high",
                waf_bypass=True,
            )
        ]
        risk = detector.assess_hpp_risk(vulns)
        assert risk == "critical"

    def test_get_hpp_summary(self):
        detector = HPPDetector()
        detector._vulnerabilities = [
            HPPVulnerability(
                parameter="test",
                pollution_type="test",
                payload="test",
                url="test",
                severity="high",
                waf_bypass=True,
            )
        ]
        summary = detector.get_hpp_summary()
        assert summary["total_vulnerabilities"] == 1
        assert summary["waf_bypass"] == 1


class TestCookieXSS:
    """Test cookie-based XSS detection."""

    def test_detects_document_cookie(self):
        detector = CookieXSSDetector()
        js = "const cookie = document.cookie"
        sinks = detector.detect_cookie_sinks(js)
        assert CookieSink.DOCUMENT_COOKIE in sinks

    def test_detects_cookie_header(self):
        detector = CookieXSSDetector()
        js = "const cookie = request.headers.cookie"
        sinks = detector.detect_cookie_sinks(js)
        assert CookieSink.COOKIE_HEADER in sinks

    def test_check_attribute_bypass(self):
        detector = CookieXSSDetector()
        header = "session=abc; SameSite=None; Secure"
        bypasses = detector.check_attribute_bypass(header)
        assert len(bypasses) > 0

    def test_generates_cookie_payloads(self):
        detector = CookieXSSDetector()
        payloads = detector.generate_cookie_payloads(CookieSink.DOCUMENT_COOKIE, "marker")
        assert len(payloads) > 0
        assert any("marker" in p for p in payloads)

    def test_test_cookie_injection_returns_vulnerability(self):
        detector = CookieXSSDetector()
        vuln = detector.test_cookie_injection("session", CookieSink.DOCUMENT_COOKIE, "marker")
        assert vuln is not None
        assert vuln.sink == CookieSink.DOCUMENT_COOKIE

    def test_scan_returns_vulnerabilities(self):
        detector = CookieXSSDetector()
        js = "const cookie = document.cookie"
        vulns = detector.scan_for_cookie_xss(js)
        assert len(vulns) > 0

    def test_assess_cookie_xss_risk_critical(self):
        detector = CookieXSSDetector()
        vulns = [
            CookieXSSVulnerability(
                sink=CookieSink.DOCUMENT_COOKIE,
                injection_point="session",
                context="test",
                payload="<script>alert(1)</script>",
                severity="high",
                bypass_attributes=["samesite"],
            )
        ]
        risk = detector.assess_cookie_xss_risk(vulns)
        assert risk == "critical"

    def test_get_cookie_xss_summary(self):
        detector = CookieXSSDetector()
        detector._vulnerabilities = [
            CookieXSSVulnerability(
                sink=CookieSink.DOCUMENT_COOKIE,
                injection_point="test",
                context="test",
                payload="test",
                severity="high",
                bypass_attributes=[],
            )
        ]
        summary = detector.get_cookie_xss_summary()
        assert summary["total_vulnerabilities"] == 1


class TestWebComponents:
    """Test web component XSS detection."""

    def test_detects_custom_elements(self):
        detector = WebComponentDetector()
        js = "customElements.define('my-element', class extends HTMLElement {})"
        detected = detector.detect_components("", js)
        assert ComponentType.CUSTOM_ELEMENT in detected

    def test_detects_shadow_dom(self):
        detector = WebComponentDetector()
        js = "this.attachShadow({mode: 'open'})"
        detected = detector.detect_components("", js)
        assert ComponentType.SHADOW_DOM in detected

    def test_detects_template(self):
        detector = WebComponentDetector()
        html = '<template id="my-template">content</template>'
        detected = detector.detect_components(html, "")
        assert ComponentType.TEMPLATE in detected

    def test_detect_custom_elements_names(self):
        detector = WebComponentDetector()
        js = "customElements.define('my-element', MyElement)"
        elements = detector.detect_custom_elements(js)
        assert "my-element" in elements

    def test_check_shadow_dom_xss(self):
        detector = WebComponentDetector()
        js = "this.shadowRoot.innerHTML = user_input"
        vulns = detector.check_shadow_dom_xss(js, "marker")
        assert len(vulns) > 0

    def test_check_template_xss(self):
        detector = WebComponentDetector()
        html = '<template><script>alert(1)</script></template>'
        vulns = detector.check_template_xss(html, "", "marker")
        assert len(vulns) > 0

    def test_check_lifecycle_xss(self):
        detector = WebComponentDetector()
        js = "connectedCallback() { this.innerHTML = input }"
        vulns = detector.check_lifecycle_xss(js, "marker")
        assert len(vulns) > 0

    def test_scan_returns_vulnerabilities(self):
        detector = WebComponentDetector()
        html = '<template id="test"></template>'
        js = "customElements.define('test', class extends HTMLElement { connectedCallback() { this.shadowRoot.innerHTML = input } })"
        vulns = detector.scan_for_web_component_xss(html, js, "marker")
        assert len(vulns) > 0

    def test_assess_component_risk_critical(self):
        detector = WebComponentDetector()
        vulns = [
            WebComponentVulnerability(
                component_type=ComponentType.SHADOW_DOM,
                element_name="test",
                injection_point="test",
                context="test",
                payload="<script>alert(1)</script>",
                severity="high",
            )
        ]
        risk = detector.assess_component_risk(vulns)
        assert risk == "critical"

    def test_get_component_summary(self):
        detector = WebComponentDetector()
        detector._vulnerabilities = [
            WebComponentVulnerability(
                component_type=ComponentType.SHADOW_DOM,
                element_name="test",
                injection_point="test",
                context="test",
                payload="test",
                severity="high",
            )
        ]
        summary = detector.get_component_summary()
        assert summary["total_vulnerabilities"] == 1


class TestWASMXSS:
    """Test WebAssembly XSS detection."""

    def test_detects_wasm_module(self):
        detector = WASMXSSDetector()
        js = "const module = new WebAssembly.Module(buffer)"
        sinks = detector.detect_wasm_sinks(js)
        assert WASMSink.WASM_MODULE in sinks

    def test_detects_wasm_instance(self):
        detector = WASMXSSDetector()
        js = "WebAssembly.instantiate(buffer)"
        sinks = detector.detect_wasm_sinks(js)
        assert WASMSink.WASM_INSTANCE in sinks

    def test_detects_wasm_memory(self):
        detector = WASMXSSDetector()
        js = "const memory = new WebAssembly.Memory({initial: 10})"
        sinks = detector.detect_wasm_sinks(js)
        assert WASMSink.WASM_MEMORY in sinks

    def test_detect_wasm_files(self):
        detector = WASMXSSDetector()
        html = '<script src="module.wasm"></script>'
        files = detector.detect_wasm_files(html)
        assert len(files) > 0

    def test_check_dangerous_integration(self):
        detector = WASMXSSDetector()
        js = "eval(instance.exports.test)"
        vulns = detector.check_dangerous_integration(js, "marker")
        assert len(vulns) > 0

    def test_check_wasm_memory_xss(self):
        detector = WASMXSSDetector()
        js = "const wasmMemory = new WebAssembly.Memory(); document.body.innerHTML = wasmMemory.buffer"
        vulns = detector.check_wasm_memory_xss(js, "marker")
        assert len(vulns) > 0

    def test_check_wasm_function_pointer_hijack(self):
        detector = WASMXSSDetector()
        js = "table.set(user_input, func_ptr)"
        vulns = detector.check_wasm_function_pointer_hijack(js, "marker")
        assert len(vulns) > 0

    def test_scan_returns_vulnerabilities(self):
        detector = WASMXSSDetector()
        js = "WebAssembly.instantiate(buffer); eval(instance.exports.test)"
        vulns = detector.scan_for_wasm_xss("", js, "marker")
        assert len(vulns) > 0

    def test_assess_wasm_risk_critical(self):
        detector = WASMXSSDetector()
        vulns = [
            WASMXSSVulnerability(
                sink=WASMSink.WASM_MEMORY,
                injection_point="test",
                context="test",
                payload="<script>alert(1)</script>",
                severity="critical",
            )
        ]
        risk = detector.assess_wasm_risk(vulns)
        assert risk == "critical"

    def test_get_wasm_summary(self):
        detector = WASMXSSDetector()
        detector._vulnerabilities = [
            WASMXSSVulnerability(
                sink=WASMSink.WASM_MEMORY,
                injection_point="test",
                context="test",
                payload="test",
                severity="critical",
            )
        ]
        summary = detector.get_wasm_summary()
        assert summary["total_vulnerabilities"] == 1


class TestClipboardXSS:
    """Test clipboard XSS detection."""

    def test_detects_clipboard_write(self):
        detector = ClipboardXSSDetector()
        js = "navigator.clipboard.writeText(text)"
        sinks = detector.detect_clipboard_sinks(js)
        assert ClipboardSink.CLIPBOARD_WRITE in sinks

    def test_detects_clipboard_read(self):
        detector = ClipboardXSSDetector()
        js = "navigator.clipboard.readText()"
        sinks = detector.detect_clipboard_sinks(js)
        assert ClipboardSink.CLIPBOARD_READ in sinks

    def test_detects_paste_event(self):
        detector = ClipboardXSSDetector()
        js = "addEventListener('paste', handler)"
        sinks = detector.detect_clipboard_sinks(js)
        assert ClipboardSink.PASTE_EVENT in sinks

    def test_check_dangerous_integration(self):
        detector = ClipboardXSSDetector()
        js = "innerHTML = clipboardData.getData('text')"
        vulns = detector.check_dangerous_integration(js, "marker")
        assert len(vulns) > 0

    def test_check_paste_event_xss(self):
        detector = ClipboardXSSDetector()
        js = "onpaste = (e) => { this.innerHTML = e.clipboardData.getData('text') }"
        vulns = detector.check_paste_event_xss(js, "marker")
        assert len(vulns) > 0

    def test_check_clipboard_reflection(self):
        detector = ClipboardXSSDetector()
        js = "const text = await navigator.clipboard.readText(); document.body.innerHTML = text"
        vulns = detector.check_clipboard_reflection(js, "marker")
        assert len(vulns) > 0

    def test_check_exec_command_xss(self):
        detector = ClipboardXSSDetector()
        js = "document.execCommand('paste', false, user_input)"
        vulns = detector.check_exec_command_xss(js, "marker")
        assert len(vulns) > 0

    def test_scan_returns_vulnerabilities(self):
        detector = ClipboardXSSDetector()
        js = "addEventListener('paste', (e) => { this.innerHTML = e.clipboardData.getData('text') })"
        vulns = detector.scan_for_clipboard_xss("", js, "marker")
        assert len(vulns) > 0

    def test_assess_clipboard_risk_critical(self):
        detector = ClipboardXSSDetector()
        vulns = [
            ClipboardXSSVulnerability(
                sink=ClipboardSink.CLIPBOARD_READ,
                injection_point="test",
                context="test",
                payload="<script>alert(1)</script>",
                severity="critical",
            )
        ]
        risk = detector.assess_clipboard_risk(vulns)
        assert risk == "critical"

    def test_get_clipboard_summary(self):
        detector = ClipboardXSSDetector()
        detector._vulnerabilities = [
            ClipboardXSSVulnerability(
                sink=ClipboardSink.CLIPBOARD_READ,
                injection_point="test",
                context="test",
                payload="test",
                severity="critical",
            )
        ]
        summary = detector.get_clipboard_summary()
        assert summary["total_vulnerabilities"] == 1
