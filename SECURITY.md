# Security Policy

## Reporting Security Issues in XOXSS

We take the security of **XOXSS** seriously. As a tool designed for authorized security assessments, it is critical that the scanner itself does not introduce security risks into operators' environments.

If you discover a security vulnerability in XOXSS (such as command injection in PoC generators, remote code execution via malicious target responses, path traversal in reporting or state stores, or sensitive data leakage in logs), please report it responsibly following the guidelines below.

---

## Supported Versions

Only the latest major version branch receives active security updates.

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 2.x.x   | :white_check_mark: | Actively supported and maintained |
| < 2.0.0 | :x:                | Deprecated; upgrade to 2.x recommended |

---

## How to Report a Vulnerability

**Please do not disclose security vulnerabilities publicly through GitHub Issues, Discussions, or pull requests.**

### Preferred Method: GitHub Private Vulnerability Reporting
You can report vulnerabilities privately and securely directly through GitHub:
1. Navigate to the [Security Advisories](https://github.com/gl1tch0x1/xoxss/security/advisories) page.
2. Click **"Report a vulnerability"** to open a confidential advisory draft.
3. Provide a clear description, reproduction steps, and proof-of-concept (PoC).

### Alternative Method: Email
If GitHub Private Advisories are unavailable, send an encrypted or direct email to:
* **Contact:** `mraashish0x1@duck.com` / GitHub maintainer: `@gl1tch0x1`
* **Subject:** `[Vulnerability Report] XOXSS - <brief-summary>`

---

## What to Include in Your Report

To help us triage and resolve the issue quickly, please include:
1. **Description & Severity:** A detailed explanation of the vulnerability and its potential security impact.
2. **Component Affected:** The specific file, module, or CLI flag involved (e.g. `xoxss/core/browser.py`, `--replay`, report exporters).
3. **Proof-of-Concept:** Step-by-step instructions or minimal reproducible test case (e.g. sample HTTP response, mock server, or command).
4. **Environment:** OS / platform, Python version, browser engine (`playwright` / `selenium`), and XOXSS version (`xoxss --version`).
5. **Mitigation Suggestion:** Any patches, mitigations, or defensive recommendations if available.

---

## Response Process & Timeline

1. **Initial Acknowledgment:** We will acknowledge receipt of your report within **48 hours**.
2. **Triage & Validation:** We will investigate and confirm the report within **5 business days**, providing an initial severity rating and mitigation plan.
3. **Patch Development:** A fix will be developed and tested in a private repository branch.
4. **Coordinated Disclosure:** We will coordinate with you on a mutual disclosure timeline (typically within 30 days) and credit your research in the GitHub Security Advisory and release changelog.

---

## Scope & Non-Vulnerabilities

### In Scope
- Arbitrary code execution or command injection triggered by scanner actions (e.g., shell escaping flaws in `poc_command`, curl generation, or replay handlers).
- Path traversal or arbitrary file write vulnerabilities in report generators (`--report`) or checkpoint stores (`--state-dir`).
- SSRF or local service exposure in built-in mock/fixture servers or callback receivers.
- Leakage of sensitive tokens or credentials outside designated directories.

### Out of Scope
- Vulnerabilities discovered on target web applications scanned with XOXSS (report those directly to the target organization's security team or bug bounty program).
- Denial-of-service against the scanner via infinite loops on adversarial, non-terminating web pages.
- Issues requiring root/administrator compromise of the operator's machine.
- Social engineering attacks against the project maintainers.

---

## Safe Harbor

We consider good-faith security research into XOXSS itself to be authorized conduct. We will not pursue legal action against researchers who:
- Make a good-faith effort to avoid privacy violations, data destruction, and interruption of services.
- Provide us a reasonable period to remediate the vulnerability before public disclosure.
- Comply with all applicable laws and adhere to responsible disclosure best practices.
