#!/usr/bin/env python3
import json
import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: parse_dependencycheck.py <dependency-check-report.json>", file=sys.stderr)
        sys.exit(1)

    report_path = sys.argv[1]

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file '{report_path}': {e}", file=sys.stderr)
        sys.exit(1)

    vulnerabilities = data.get('dependencies', [])
    total_vulns = 0
    severity_count = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Info': 0
    }

    print("="*60)
    print(f"Dependency-Check Vulnerability Report Summary")
    print("="*60)
    print(f"Total dependencies scanned: {len(vulnerabilities)}\n")

    for dep in vulnerabilities:
        vulns = dep.get('vulnerabilities', [])
        if not vulns:
            continue

        print(f"Dependency: {dep.get('fileName', 'Unknown')}")
        for vuln in vulns:
            total_vulns += 1
            severity = vuln.get('severity', 'Unknown').capitalize()
            severity_count[severity] = severity_count.get(severity, 0) + 1

            cve = vuln.get('name', 'N/A')
            description = vuln.get('description', '').strip().replace('\n', ' ')
            url = vuln.get('references', [{}])[0].get('url', 'N/A')

            print(f"  - [{severity}] {cve}")
            print(f"      Description: {description[:200]}{'...' if len(description) > 200 else ''}")
            print(f"      More info: {url}")
        print("")

    print("="*60)
    print(f"Total vulnerabilities found: {total_vulns}")
    print("Severity breakdown:")
    for level in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        print(f"  {level}: {severity_count.get(level, 0)}")
    print("="*60)


if __name__ == "__main__":
    main()
