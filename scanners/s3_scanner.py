import boto3

def scan_s3():
    findings = [
        {
            "service": "S3",
            "resource": "company-public-assets",
            "issue": "S3 bucket is publicly accessible",
            "severity": "CRITICAL",
            "remediation": "Block public access to the S3 bucket"
        },
        {
            "service": "S3",
            "resource": "customer-data-backups",
            "issue": "S3 bucket does not have server-side encryption enabled",
            "severity": "HIGH",
            "remediation": "Enable default encryption for the S3 bucket"
        }
    ]
    return findings


if __name__ == "__main__":
    results = scan_s3()

    print("\n=== S3 SECURITY SCAN ===")

    if not results:
        print("No security issues found.")
    else:
        for finding in results:
            print(f"\nService: {finding['service']}")
            print(f"Resource: {finding['resource']}")
            print(f"Issue: {finding['issue']}")
            print(f"Severity: {finding['severity']}")
            print(f"Remediation: {finding['remediation']}")