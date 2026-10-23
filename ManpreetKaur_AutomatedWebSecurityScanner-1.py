"""
Project: Automated Web Security Scanner Using Python
Purpose: Educational first-pass review of HTTP security headers and basic CORS response headers.

Responsible use:
- Scan only websites you own or have explicit permission to test.
- This tool sends a small number of GET requests.
- It does not exploit vulnerabilities and is not a complete security audit.
"""
import argparse
import json
import sys
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency. Install with: python -m pip install -r requirements.txt")
    sys.exit(1)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps browsers enforce HTTPS after a secure visit.",
    "Content-Security-Policy": "Restricts allowed content sources and can reduce some injection risks.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing; commonly set to nosniff.",
    "X-Frame-Options": "Can help reduce clickjacking; CSP frame-ancestors is a modern alternative.",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Restricts selected browser features.",
}
USER_AGENT = "IBM-SkillsBuild-Educational-Web-Scanner/1.0"


def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Provide a full URL beginning with http:// or https://")
    return url


def scan(url, timeout=8):
    validate_url(url)
    result = {
        "requested_url": url,
        "final_url": None,
        "status_code": None,
        "https": urlparse(url).scheme == "https",
        "headers": {},
        "cors": {},
        "errors": [],
    }
    headers = {"User-Agent": USER_AGENT}
    try:
        response = requests.get(
            url, timeout=timeout, allow_redirects=True, headers=headers
        )
        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["https"] = urlparse(response.url).scheme == "https"

        for name, purpose in SECURITY_HEADERS.items():
            value = response.headers.get(name)
            result["headers"][name] = {
                "present": value is not None,
                "value": value,
                "purpose": purpose,
            }

        try:
            cors_response = requests.get(
                response.url,
                timeout=timeout,
                allow_redirects=True,
                headers={
                    "User-Agent": USER_AGENT,
                    "Origin": "https://scanner-test.invalid",
                },
            )
            allow_origin = cors_response.headers.get("Access-Control-Allow-Origin")
            allow_credentials = cors_response.headers.get(
                "Access-Control-Allow-Credentials", ""
            ).lower()
            result["cors"] = {
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_credentials or None,
                "wildcard_origin": allow_origin == "*",
                "reflects_test_origin": allow_origin == "https://scanner-test.invalid",
                "note": (
                    "These are response-header observations, not proof of exploitability. "
                    "CORS risk depends on the endpoint, credentials, data sensitivity, "
                    "and browser behavior."
                ),
            }
        except requests.RequestException as exc:
            result["errors"].append(f"CORS observation failed: {exc}")

    except requests.RequestException as exc:
        result["errors"].append(f"HTTP request failed: {exc}")
    return result


def print_report(result):
    print("\n=== Automated Web Security Scanner ===")
    print(f"Requested URL: {result['requested_url']}")
    print(f"Final URL:     {result['final_url'] or 'Not reached'}")
    print(f"HTTP status:   {result['status_code'] or 'Unavailable'}")
    print(f"HTTPS:         {'Yes' if result['https'] else 'No'}")

    print("\n--- Security headers ---")
    for name, details in result["headers"].items():
        label = "PRESENT" if details["present"] else "MISSING"
        print(f"[{label}] {name}")
        if details["value"]:
            print(f"    Value: {details['value']}")
        print(f"    Purpose: {details['purpose']}")

    print("\n--- Basic CORS observation ---")
    if result["cors"]:
        print("Access-Control-Allow-Origin:",
              result["cors"].get("access_control_allow_origin") or "Not present")
        print("Access-Control-Allow-Credentials:",
              result["cors"].get("access_control_allow_credentials") or "Not present")
        if result["cors"].get("wildcard_origin"):
            print("Observation: wildcard origin was returned; review context.")
        if result["cors"].get("reflects_test_origin"):
            print("Observation: test Origin value was reflected; review context.")
        print(result["cors"]["note"])
    else:
        print("CORS observation unavailable.")

    if result["errors"]:
        print("\n--- Errors ---")
        for error in result["errors"]:
            print("-", error)

    missing = [
        name for name, details in result["headers"].items()
        if not details["present"]
    ]
    print(f"\nMissing security headers: {len(missing)} of {len(SECURITY_HEADERS)}")
    if missing:
        print("Review these headers:", ", ".join(missing))
    print("Reminder: missing headers or CORS signals are not, by themselves, proof of a vulnerability.")


def main():
    parser = argparse.ArgumentParser(
        description="Educational scanner for HTTP security headers and basic CORS response headers."
    )
    parser.add_argument("url", help="URL of a website you own or are authorized to test")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    parser.add_argument("--json", dest="json_file", help="Save results to a JSON file")
    args = parser.parse_args()

    try:
        result = scan(args.url, timeout=max(1, args.timeout))
    except ValueError as exc:
        parser.error(str(exc))

    print_report(result)
    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_file}")


if __name__ == "__main__":
    main()
