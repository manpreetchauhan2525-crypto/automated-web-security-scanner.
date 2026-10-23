# Automated Web Security Scanner Using Python

## Project description
This educational project checks a website's HTTP response for six commonly used security headers and records a limited set of Cross-Origin Resource Sharing (CORS) response headers. It prints a readable summary and can optionally save results as JSON.

The tool is intended for defensive learning and authorized testing. It makes a small number of ordinary GET requests, does not exploit systems, and does not prove that a website is secure or insecure.

## Objectives
- Check whether selected security headers are present.
- Record HTTP status, final URL, and whether the final URL uses HTTPS.
- Observe `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.
- Print a terminal report and optionally export JSON.
- Practice responsible security testing and evidence-based reporting.

## Technologies used
- Python 3.9 or newer
- `requests` library
- JSON for optional report export
- Command line / terminal

## Files
- `ManpreetKaur_AutomatedWebSecurityScanner.py` — project source code
- `requirements.txt` — Python dependency list
- `ManpreetKaur_ProjectReport.docx` — project report

## Installation
1. Install Python 3.9+.
2. Open a terminal in the project folder.
3. Install the dependency:

   ```bash
   python -m pip install -r requirements.txt
   ```

## Run the project
Use only a website you own or have explicit permission to test.

```bash
python ManpreetKaur_AutomatedWebSecurityScanner.py https://your-authorized-test-site.example
```

Save a JSON report:

```bash
python ManpreetKaur_AutomatedWebSecurityScanner.py https://your-authorized-test-site.example --json report.json
```

## Security headers checked
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

## CORS observation
The program sends a harmless test `Origin` header and records the server's CORS response headers. A wildcard or reflected origin is only a signal for manual review, not proof of a vulnerability. Actual risk depends on the endpoint, credentials, data sensitivity, and browser behavior.

## Dataset
No external dataset is required. This project performs live HTTP response-header checks against a user-provided, authorized test website. For safe demonstrations, use a local lab or a site you control. Do not scan unrelated sites without permission.

## Limitations
- Checks one URL at a time and does not crawl the site.
- Does not test authentication, session handling, authorization, or business logic.
- Does not evaluate every detail of a security policy.
- A missing header is not automatically a vulnerability.
- Not a replacement for a full security audit.

## Responsible use
Only test systems you own or have explicit permission to assess. Follow the program's rules and your institution's policies. Do not use the tool to disrupt services or bypass access controls.

## References
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- Python requests documentation: https://requests.readthedocs.io/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
