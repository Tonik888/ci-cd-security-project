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

    # Count severities as before
    for issue in issues:
        severity = issue.get('severity', 'INFO').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['INFO'] += 1

    total_issues = len(issues)

    # Group issues by type for sorting output
    issues_by_type = {
        "CODE_SMELL": [],
        "BUG": [],
        "VULNERABILITY": []
    }

    for issue in issues:
        issue_type = issue.get('type', 'CODE_SMELL').upper()
        if issue_type in issues_by_type:
            issues_by_type[issue_type].append(issue)
        else:
            # If other types appear, add them to CODE_SMELL by default or ignore
            issues_by_type["CODE_SMELL"].append(issue)

    # Write output to sonar_summary.txt
    with open('sonar_summary.txt', 'w') as out:
        out.write(f"Total Issues: {total_issues}\n")
        out.write("Severity Breakdown:\n")
        for sev, count in severity_counts.items():
            out.write(f"  {sev}: {count}\n")

        out.write("\nIssues sorted by type:\n")

        # Order matters: code_smell, bug, vulnerability
        for issue_type in ["CODE_SMELL", "BUG", "VULNERABILITY"]:
            out.write(f"\n=== {issue_type} ({len(issues_by_type[issue_type])}) ===\n")
            for issue in issues_by_type[issue_type]:
                # Customize the fields you want to see for each issue
                key = issue.get('key', 'N/A')
                severity = issue.get('severity', 'N/A')
                component = issue.get('component', 'N/A')
                message = issue.get('message', '').replace('\n', ' ')
                line = issue.get('line', 'N/A')
                out.write(f"- [{severity}] {key} at {component}:{line} - {message}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_sonarqube.py <sonar_report.json>")
        sys.exit(1)
    parse_sonarqube(sys.argv[1])
