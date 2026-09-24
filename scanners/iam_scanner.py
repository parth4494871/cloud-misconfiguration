import boto3

def scan_iam():
    findings = [
        {
            "service": "IAM",
            "resource": "admin-user",
            "issue": "IAM user does not have MFA enabled",
            "severity": "HIGH",
            "remediation": "Enable MFA for the IAM user"
        },
        {
            "service": "IAM",
            "resource": "dev-user-2",
            "issue": "IAM access key is older than 90 days",
            "severity": "MEDIUM",
            "remediation": "Rotate access keys regularly"
        }
    ]
    return findings


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