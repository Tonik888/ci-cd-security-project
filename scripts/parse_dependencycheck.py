import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

def parse_dependency_check_xml(xml_path):
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading XML file: {e}")
        return

    # Updated XML namespace (used in newer reports)
    ns = {'ns': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd'}

    # Severity counters
    severity_counts = defaultdict(int)

    # Detailed list
    details = []

    for dependency in root.findall(".//ns:dependency", ns):
        package = dependency.findtext("ns:fileName", default="Unknown", namespaces=ns)
        for vuln in dependency.findall("ns:vulnerabilities/ns:vulnerability", ns):
            cve_id = vuln.findtext("ns:name", default="N/A", namespaces=ns)
            severity = vuln.findtext("ns:severity", default="UNKNOWN", namespaces=ns).capitalize()
            description = vuln.findtext("ns:description", default="No description", namespaces=ns).replace('\n', ' ')
            recommendation = vuln.findtext("ns:recommendation", default="No recommendation", namespaces=ns)

            severity_counts[severity] += 1
            details.append({
                "Package": package,
                "CVE_ID": cve_id,
                "Severity": severity,
                "Description": description[:100] + "...",
                "Recommendation": recommendation
            })

    # Summary
    total = sum(severity_counts.values())
    print("Dependency-Check Vulnerability Summary:")
    print(f"  Total Vulnerabilities: {total}")
    for sev, count in severity_counts.items():
        print(f"  {sev}: {count}")

    # Detail Table
    print("\nTop Vulnerability Details:")
    print(f"{'Package':<25} {'CVE_ID':<20} {'Severity':<10} {'Description (truncated)':<60}")
    for d in details[:10]:  # Show top 10 for brevity
        print(f"{d['Package']:<25} {d['CVE_ID']:<20} {d['Severity']:<10} {d['Description']:<60}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 parse_dependencycheck.py <dependency-check-report.xml>")
        sys.exit(1)

    parse_dependency_check_xml(sys.argv[1])
