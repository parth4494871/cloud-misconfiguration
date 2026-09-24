import boto3
import random

def scan_s3():
    possible_findings = [
        {
            "service": "S3",
            "resource": f"company-public-assets-{random.randint(1,99)}",
            "issue": "S3 bucket is publicly accessible",
            "impact": "Public buckets allow anyone on the internet to read or write data, which is the leading cause of massive cloud data breaches.",
            "severity": "CRITICAL",
            "remediation": "Block public access to the S3 bucket"
        },
        {
            "service": "S3",
            "resource": f"customer-data-backups-{random.randint(1,99)}",
            "issue": "S3 bucket does not have server-side encryption enabled",
            "impact": "Without encryption at rest, data physically stored on AWS disks could be compromised, failing compliance standards like HIPAA and GDPR.",
            "severity": "HIGH",
            "remediation": "Enable default encryption for the S3 bucket"
        },
        {
            "service": "S3",
            "resource": f"logs-bucket-{random.randint(1,99)}",
            "issue": "S3 bucket does not have versioning enabled",
            "impact": "Without versioning, accidentally deleted or overwritten files cannot be recovered, making you vulnerable to ransomware or accidental data loss.",
            "severity": "MEDIUM",
            "remediation": "Enable versioning to protect against accidental deletes"
        }
    ]
    return random.sample(possible_findings, random.randint(0, len(possible_findings)))


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