import sys
import xml.etree.ElementTree as ET

def parse_dependency_check_xml(xml_path):
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading XML file: {e}")
        return

    # Register namespace based on XML file
    ns = {'ns': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd'}

    # Initialize severity counters
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Unknown': 0
    }

    # Find all vulnerability elements using namespace-aware XPath
    for vulnerability in root.findall('.//ns:vulnerabilities/ns:vulnerability', ns):
        severity_elem = vulnerability.find('ns:severity', ns)
        if severity_elem is not None and severity_elem.text:
            sev_text = severity_elem.text.strip()
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
