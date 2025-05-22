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

    prompt = "\nDependency-Check Findings:\n"
    count = 0

    for dependency in root.findall(".//ns:dependency", ns):
        package = dependency.findtext("ns:fileName", default="Unknown", namespaces=ns)
        for vuln in dependency.findall("ns:vulnerabilities/ns:vulnerability", ns):
            name = vuln.findtext("ns:name", "Unknown", namespaces=ns)
            severity = vuln.findtext("ns:severity", "Unknown", namespaces=ns)
            description = vuln.findtext("ns:description", "", namespaces=ns).replace('\n', ' ')[:120]
            prompt += f"- Package: {package}, Severity: {severity}, CVE: {name}, Description: {description}...\n"
            count += 1
            if count >= 10:
                return prompt
    if count == 0:
        prompt += "No vulnerabilities found in Dependency-Check report.\n"
    return prompt

def build_prompt(sonar_data, trivy_data, depcheck_text):
    prompt = "Based on the following security and code quality issues, provide prioritized recommendations:\n\n"

    prompt += "SonarQube Issues:\n"
    issues = sonar_data.get('issues', [])
    if not issues:
        prompt += "No issues found.\n"
    else:
        for issue in issues[:10]:
            prompt += f"- Severity: {issue.get('severity')}, Type: {issue.get('type')}, File: {issue.get('component')}, Message: {issue.get('message')}\n"

    prompt += "\nTrivy Vulnerabilities:\n"
    vulnerabilities = trivy_data.get('Results', [])
    count = 0
    for target in vulnerabilities:
        vulns = target.get('Vulnerabilities', [])
        for vuln in vulns[:5]:
            prompt += f"- Severity: {vuln.get('Severity')}, Package: {vuln.get('PkgName')}, VulnerabilityID: {vuln.get('VulnerabilityID')}, Description: {vuln.get('Description')[:100]}...\n"
            count += 1
            if count >= 10:
                break
        if count >= 10:
            break

    prompt += depcheck_text
    prompt += "\n\nPlease provide concise, prioritized mitigation strategies and development best practices."
    return prompt

def main():
    if len(sys.argv) != 5:
        print("Usage: python generate_openai_recommendations.py <sonar-json> <trivy-json> <depcheck-xml> <openai-api-key>")
        sys.exit(1)

    sonar_file = sys.argv[1]
    trivy_file = sys.argv[2]
    depcheck_file = sys.argv[3]
    openai_api_key = sys.argv[4]

    # Load data
    sonar_data = load_json(sonar_file)
    trivy_data = load_json(trivy_file)
    depcheck_text = parse_dependency_check_xml(depcheck_file)

    # Build prompt and call OpenAI
    prompt = build_prompt(sonar_data, trivy_data, depcheck_text)

    client = OpenAI(api_key=openai_api_key)
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=600,
        temperature=0.7,
    )

    recommendation = response.choices[0].message.content
    print("=== OpenAI GPT-3.5 Recommendations ===\n")
    print(recommendation)

if __name__ == "__main__":
    main()
