import json
import sys

def parse_sonarqube(json_path):
    with open(json_path, 'r') as f:
        data = json.load(f)

    issues = data.get('issues', [])

    # Initialize severity counts
    severity_counts = {
        "BLOCKER": 0,
        "CRITICAL": 0,
        "MAJOR": 0,
        "MINOR": 0,
        "INFO": 0
    }
    
    # Initialize type counts
    type_counts = {
        "CODE_SMELL": 0,
        "BUG": 0,
        "VULNERABILITY": 0
    }

    for issue in issues:
        # Count severity
        severity = issue.get('severity', 'INFO').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['INFO'] += 1
        
        # Count type
        issue_type = issue.get('type', '').upper()
        if issue_type in type_counts:
            type_counts[issue_type] += 1

    total_issues = len(issues)

    print(f"Total Issues: {total_issues}\n")

    print("Severity Breakdown:")
    for sev, count in severity_counts.items():
        print(f"  {sev}: {count}")
    
    print("\nType Breakdown:")
    for t, count in type_counts.items():
        print(f"  {t}: {count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_sonarqube.py <sonar_report.json>")
        sys.exit(1)
    parse_sonarqube(sys.argv[1])
