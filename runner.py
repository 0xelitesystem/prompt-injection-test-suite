#!/usr/bin/env python3
"""
prompt-injection-test-suite runner

Usage:
  python runner.py --target <url> --tests tests/direct/ [--api-key KEY]
  python runner.py --target <url> --tests tests/ --recursive
  python runner.py --dry-run --tests tests/direct/

The runner sends each YAML test's payload to your target endpoint and reports
which attacks succeeded (your model complied with the injection).

This is a skeleton. The exact request format depends on your application;
edit `send_request()` to match your API.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from urllib import request, error


def load_tests(tests_path, recursive=False):
    """Load all YAML test files from the given path."""
    p = Path(tests_path)
    if not p.exists():
        print(f"Error: tests path does not exist: {tests_path}", file=sys.stderr)
        sys.exit(1)

    if p.is_file():
        return [parse_test(p)]

    pattern = "**/*.yaml" if recursive else "*.yaml"
    files = sorted(p.glob(pattern))
    return [parse_test(f) for f in files]


def parse_test(path):
    """Parse a YAML test file using minimal hand-written parser (no PyYAML dependency).

    Tests use a small YAML subset: top-level keys, scalar values, multi-line strings via |.
    For complex YAML, install pyyaml and replace this with yaml.safe_load.
    """
    text = path.read_text(encoding="utf-8")
    test = {"_path": str(path)}
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.startswith("#"):
            i += 1
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val == "|":
                # Multi-line block
                content_lines = []
                i += 1
                while i < len(lines) and (lines[i].startswith("  ") or not lines[i].strip()):
                    content_lines.append(lines[i][2:] if lines[i].startswith("  ") else lines[i])
                    i += 1
                test[key] = "\n".join(content_lines).rstrip()
                continue
            else:
                test[key] = val
        i += 1
    return test


def send_request(target_url, payload, api_key=None):
    """Send the payload to the target endpoint and return the response.

    EDIT THIS to match your API. The default assumes a simple JSON POST
    with {"message": payload}. Adjust headers, body shape, and parsing
    as needed.
    """
    body = json.dumps({"message": payload}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = request.Request(target_url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}"
    except error.URLError as e:
        return f"Network error: {e.reason}"


def main():
    parser = argparse.ArgumentParser(description="Run prompt injection tests against your endpoint")
    parser.add_argument("--target", help="URL of your chat/completion endpoint")
    parser.add_argument("--tests", required=True, help="Path to a test file or directory")
    parser.add_argument("--recursive", "-r", action="store_true", help="Walk into subdirectories")
    parser.add_argument("--api-key", help="API key for the target endpoint")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between requests (default 1.0)")
    parser.add_argument("--dry-run", action="store_true", help="Load and print tests without sending")
    args = parser.parse_args()

    tests = load_tests(args.tests, recursive=args.recursive)
    print(f"Loaded {len(tests)} tests")

    if args.dry_run:
        for t in tests:
            print(f"\n--- {t.get('id', '?')} [{t.get('category', '?')}] severity={t.get('severity', '?')} ---")
            print(f"Goal: {t.get('goal', '')}")
            print(f"Payload (first 200 chars): {t.get('payload', '')[:200]}")
        return

    if not args.target:
        print("Error: --target is required unless --dry-run", file=sys.stderr)
        sys.exit(1)

    results = []
    for i, t in enumerate(tests, 1):
        print(f"\n[{i}/{len(tests)}] {t.get('id', '?')}: {t.get('goal', '')}")
        response = send_request(args.target, t.get("payload", ""), api_key=args.api_key)
        # Naive judgment: caller should write better detection logic.
        # This is a placeholder that always logs the response for manual review.
        results.append({
            "test_id": t.get("id"),
            "category": t.get("category"),
            "severity": t.get("severity"),
            "response": response[:500] + "..." if len(response) > 500 else response,
        })
        print(f"  Response (first 200 chars): {response[:200]}")
        time.sleep(args.delay)

    # Summary
    print("\n" + "=" * 60)
    print(f"Completed {len(results)} tests")
    print("Manual review required. The runner does not auto-judge pass/fail")
    print("because pass criteria depend on your application's expected response.")
    print("\nWrite a custom judge function for automated CI integration.")


if __name__ == "__main__":
    main()
