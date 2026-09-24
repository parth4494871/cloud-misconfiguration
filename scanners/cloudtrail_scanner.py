import json


def scan_cloudtrail():
    findings = []

    with open("cloudtrail_data.json", "r") as file:
        data = json.load(file)

    if not data.get("enabled", False):
        findings.append({
            "service": "CloudTrail",
            "resource": data.get("name", "default-trail"),
            "issue": "CloudTrail is disabled",
            "severity": "HIGH",
            "remediation": "Enable CloudTrail logging"
        })

    return findings


if __name__ == "__main__":
    results = scan_cloudtrail()

    print("\n=== CLOUDTRAIL SECURITY SCAN ===")

    if not results:
        print("No security issues found.")
    else:
        for finding in results:
            print(f"\nService: {finding['service']}")
            print(f"Resource: {finding['resource']}")
            print(f"Issue: {finding['issue']}")
            print(f"Severity: {finding['severity']}")
            print(f"Remediation: {finding['remediation']}")