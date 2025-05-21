import json
import sys

def parse_sonarqube(json_path):
    with open(json_path, 'r') as f:
        data = json.load(f)

    issues = data.get('issues', [])
    severity_counts = {
        "BLOCKER": 0,
        "CRITICAL": 0,
        "MAJOR": 0,
        "MINOR": 0,
        "INFO": 0
    }

    for issue in issues:
        severity = issue.get('severity', 'INFO').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['INFO'] += 1

    total_issues = len(issues)

    print(f"Total Issues: {total_issues}")
    print("Severity Breakdown:")
    for sev, count in severity_counts.items():
        print(f"  {sev}: {count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_sonarqube.py <sonar_report.json>")
        sys.exit(1)
    parse_sonarqube(sys.argv[1])
