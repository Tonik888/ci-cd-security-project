import sys
import json
import openai
import xml.etree.ElementTree as ET

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def parse_dependency_check_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    prompt = "\nDependency-Check Findings:\n"
    count = 0
    for vuln in root.findall(".//vulnerability"):
        name = vuln.findtext("name", "Unknown")
        severity = vuln.findtext("severity", "Unknown")
        description = vuln.findtext("description", "")[:150].replace('\n', ' ')
        prompt += f"- Severity: {severity}, Name: {name}, Description: {description}...\n"
        count += 1
        if count >= 10:
            break
    return prompt

def build_prompt(sonar_data, trivy_data, depcheck_text):
    prompt = "Analyze the following software security and quality issues and provide practical, prioritized recommendations:\n\n"

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
    prompt += "\nPlease provide mitigation strategies, refactoring suggestions, or configuration improvements where applicable."
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
    depcheck_text = parse_dependency_check_xml(depcheck_file)

    prompt = build_prompt(sonar_data, trivy_data, depcheck_text)

    openai.api_key = openai_api_key

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=300,
        temperature=0.7,
    )

    recommendation = response.choices[0].message.content
    print("=== OpenAI GPT-3.5 Turbo Recommendations ===\n")
    print(recommendation)

if __name__ == "__main__":
    main()
