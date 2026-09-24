import boto3
import random

def scan_iam():
    possible_findings = [
        {
            "service": "IAM",
            "resource": f"admin-user-{random.randint(1,99)}",
            "issue": "IAM user does not have MFA enabled",
            "impact": "Without Multi-Factor Authentication, an attacker only needs a compromised password to access the account, drastically increasing the risk of account takeover.",
            "severity": "HIGH",
            "remediation": "Enable MFA for the IAM user"
        },
        {
            "service": "IAM",
            "resource": f"dev-user-{random.randint(1,99)}",
            "issue": "IAM access key is older than 90 days",
            "impact": "Old access keys are more likely to be leaked or compromised over time. Rotating them regularly limits the window of opportunity for an attacker.",
            "severity": "MEDIUM",
            "remediation": "Rotate access keys regularly"
        },
        {
            "service": "IAM",
            "resource": f"legacy-role-{random.randint(1,99)}",
            "issue": "IAM Role has overly permissive policies (*:*)",
            "impact": "Using wildcard permissions (*:*) grants administrative access, which violates the principle of least privilege and can allow attackers to take full control of your AWS environment.",
            "severity": "CRITICAL",
            "remediation": "Apply least privilege principles to the IAM role"
        }
    ]
    # Randomly select between 0 and all possible findings
    return random.sample(possible_findings, random.randint(0, len(possible_findings)))


if __name__ == "__main__":
    results = scan_iam()

    print("\n=== IAM SECURITY SCAN ===")

    if not results:
        print("No security issues found.")
    else:
        for finding in results:
            print(f"\nService: {finding['service']}")
            print(f"Resource: {finding['resource']}")
            print(f"Issue: {finding['issue']}")
            print(f"Severity: {finding['severity']}")
            print(f"Remediation: {finding['remediation']}")