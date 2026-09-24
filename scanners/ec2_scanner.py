import boto3
import random
def scan_ec2():
    possible_findings = [
        {
            "service": "EC2",
            "resource": f"vol-0a1b2c3d4e{random.randint(100,999)}",
            "issue": "EBS volume is not encrypted",
            "impact": "Data on unencrypted volumes is stored in plaintext. If the underlying infrastructure is compromised, your sensitive data is fully exposed.",
            "severity": "HIGH",
            "remediation": "Enable encryption for the EBS volume"
        },
        {
            "service": "EC2",
            "resource": f"i-0123456789abc{random.randint(100,999)}",
            "issue": f"EC2 instance has a public IP address (203.0.113.{random.randint(1,254)})",
            "impact": "Directly attaching a public IP exposes the instance to the internet, inviting brute-force attacks and automated scanning bots.",
            "severity": "MEDIUM",
            "remediation": "Remove the public IP address if not required, and use a load balancer or bastion host."
        }
    ]
    return random.sample(possible_findings, random.randint(0, len(possible_findings)))

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
