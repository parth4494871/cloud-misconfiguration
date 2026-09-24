import boto3
def scan_ec2():
    findings = [
        {
            "service": "EC2",
            "resource": "vol-0a1b2c3d4e5f6g7h8",
            "issue": "EBS volume is not encrypted",
            "severity": "HIGH",
            "remediation": "Enable encryption for the EBS volume"
        },
        {
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "issue": "EC2 instance has a public IP address (203.0.113.45)",
            "severity": "MEDIUM",
            "remediation": "Remove the public IP address if not required, and use a load balancer or bastion host."
        }
    ]
    return findings

if __name__ == "__main__":
    results = scan_ec2()

    print("\n=== EC2 SECURITY SCAN ===")

    if not results:
        print("No security issues found.")
    else:
        for finding in results:
            print(f"\nService: {finding['service']}")
            print(f"Resource: {finding['resource']}")
            print(f"Issue: {finding['issue']}")
            print(f"Severity: {finding['severity']}")
            print(f"Remediation: {finding['remediation']}")
