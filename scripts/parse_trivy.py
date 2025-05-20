import json
import sys

def parse_trivy(json_path):
    with open(json_path, 'r') as f:
        data = json.load(f)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    vulnerabilities = []

    for result in data.get('Results', []):
        vulnerabilities.extend(result.get('Vulnerabilities', []))

    for vuln in vulnerabilities:
        severity = vuln.get('Severity', 'UNKNOWN').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['UNKNOWN'] += 1

    total_vulns = len(vulnerabilities)

    print(f"Total Vulnerabilities: {total_vulns}")
    print("Severity Breakdown:")
    for sev, count in severity_counts.items():
        print(f"  {sev}: {count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_trivy.py <trivy_report.json>")
        sys.exit(1)
    parse_trivy(sys.argv[1])
