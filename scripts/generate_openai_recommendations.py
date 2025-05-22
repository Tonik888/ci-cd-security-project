import sys
import json
import xml.etree.ElementTree as ET
from openai import OpenAI

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def parse_dependency_check_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    ns = {'ns': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd'}

    findings = []
    for dependency in root.findall(".//ns:dependency", ns):
        package = dependency.findtext("ns:fileName", default="Unknown", namespaces=ns)
        for vuln in dependency.findall("ns:vulnerabilities/ns:vulnerability", ns):
            cve = vuln.findtext("ns:name", "N/A", namespaces=ns)
            severity = vuln.findtext("ns:severity", "Unknown", namespaces=ns).upper()
            recommendation = vuln.findtext("ns:recommendation", "", namespaces=ns).strip()
            if not recommendation:
                recommendation = f"Please update {package} to a patched version to mitigate {cve}."
            findings.append({
                "package": package,
                "cve": cve,
                "severity": severity,
                "recommendation": recommendation
            })
    return findings

def build_prompt(sonar_data, trivy_data, depcheck_findings):
    prompt = """You are a security assistant.

You will receive security and quality reports from SonarQube, Trivy, and OWASP Dependency-Check.
Your task is to analyze the issues and provide clear, structured, prioritized recommendations in this format:

1. Trivy Vulnerabilities:
   - Package: <name>, CVE ID: <id>, Severity: <level>
     Recommendation: <text>

2. SonarQube Issues:
   - File: <path>, Message: <issue>
     Recommendation: <fix>

3. Dependency-Check Issues:
   - Package: <name>, CVE: <id>, Severity: <level>
     Recommendation: <fix>

---

"""

    # SonarQube
    prompt += "1. Trivy Vulnerabilities:\n"
    vulnerabilities = trivy_data.get('Results', [])
    count = 0
    for target in vulnerabilities:
        for vuln in target.get('Vulnerabilities', []):
            prompt += f"   - Package: {vuln.get('PkgName')}, CVE ID: {vuln.get('VulnerabilityID')}, Severity: {vuln.get('Severity')}\n"
            prompt += f"     Recommendation: {vuln.get('Description')[:150]}...\n"
            count += 1
            if count >= 5:
                break
        if count >= 5:
            break

    prompt += "\n2. SonarQube Issues:\n"
    issues = sonar_data.get('issues', [])
    for issue in issues[:5]:
        prompt += f"   - File: {issue.get('component')}, Message: {issue.get('message')}\n"
        prompt += f"     Recommendation: Fix the issue type {issue.get('type')} with severity {issue.get('severity')}.\n"

    prompt += "\n3. Dependency-Check Issues:\n"
    for finding in depcheck_findings[:5]:
        prompt += f"   - Package: {finding['package']}, CVE: {finding['cve']}, Severity: {finding['severity']}\n"
        prompt += f"     Recommendation: {finding['recommendation']}\n"

    prompt += "\nPlease prioritize by severity and practicality."
    return prompt

def main():
    if len(sys.argv) != 5:
        print("Usage: python generate_openai_recommendations.py <sonar-json> <trivy-json> <depcheck-xml> <openai-api-key>")
        sys.exit(1)

    sonar_file = sys.argv[1]
    trivy_file = sys.argv[2]
    depcheck_file = sys.argv[3]
    openai_api_key = sys.argv[4]

    sonar_data = load_json(sonar_file)
    trivy_data = load_json(trivy_file)
    depcheck_findings = parse_dependency_check_xml(depcheck_file)

    prompt = build_prompt(sonar_data, trivy_data, depcheck_findings)

    client = OpenAI(api_key=openai_api_key)
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000,
        temperature=0.7,
    )

    recommendation = response.choices[0].message.content
    print("=== OpenAI GPT-3.5 Recommendations ===\n")
    print(recommendation)

if __name__ == "__main__":
    main()
