import sys
import xml.etree.ElementTree as ET

def parse_dependency_check_xml(xml_path):
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading XML file: {e}")
        return

    # Dependency-Check XML namespace (usually present, adjust if necessary)
    ns = {'ns': 'http://jeremylong.github.io/DependencyCheck/dependency-check.1.0.xsd'}

    # Counters for vulnerabilities
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Unknown': 0
    }

    # The vulnerabilities are inside /analysis/dependencies/dependency/vulnerabilities/vulnerability
    for vulnerability in root.findall('.//ns:vulnerability', ns):
        severity = vulnerability.find('ns:severity', ns)
        if severity is not None:
            sev_text = severity.text
            if sev_text in severity_counts:
                severity_counts[sev_text] += 1
            else:
                severity_counts['Unknown'] += 1
        else:
            severity_counts['Unknown'] += 1

    # Print summary report
    print("Dependency-Check Vulnerability Summary:")
    total_vulns = sum(severity_counts.values())
    print(f"  Total Vulnerabilities: {total_vulns}")
    for sev, count in severity_counts.items():
        print(f"  {sev}: {count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 parse_dependencycheck.py <dependency-check-report.xml>")
        sys.exit(1)
    parse_dependency_check_xml(sys.argv[1])
