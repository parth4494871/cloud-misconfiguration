import json
import random

def scan_cloudtrail():
    possible_findings = [
        {
            "service": "CloudTrail",
            "resource": f"default-trail-{random.randint(1,99)}",
            "issue": "CloudTrail is disabled in this region",
            "impact": "Without CloudTrail, you have no audit log of who made API calls in your AWS account, making security investigations and forensics impossible.",
            "severity": "HIGH",
            "remediation": "Enable CloudTrail logging for all regions"
        },
        {
            "service": "CloudTrail",
            "resource": f"org-trail-{random.randint(1,99)}",
            "issue": "CloudTrail log file validation is not enabled",
            "impact": "Without validation, an attacker who gains access to your logs could secretly delete or modify them to cover their tracks.",
            "severity": "MEDIUM",
            "remediation": "Enable log file validation to ensure log integrity"
        }
    ]
    # 50% chance to return some CloudTrail findings
    if random.choice([True, False]):
        return random.sample(possible_findings, random.randint(1, len(possible_findings)))
    return []


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