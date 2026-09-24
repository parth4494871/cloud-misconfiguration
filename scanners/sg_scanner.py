import boto3


def scan_security_groups():
    ec2 = boto3.client(
        "ec2",
        endpoint_url="http://localhost:4566",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test"
    )

    findings = []

    response = ec2.describe_security_groups()

    for group in response["SecurityGroups"]:
        group_name = group["GroupName"]

        for permission in group.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            for ip_range in permission.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":

                    if from_port == 22:
                        findings.append({
                            "service": "Security Group",
                            "resource": group_name,
                            "issue": "SSH port 22 is open to the internet",
                            "severity": "CRITICAL",
                            "remediation": "Restrict SSH access to trusted IP addresses"
                        })

                    elif from_port == 3389:
                        findings.append({
                            "service": "Security Group",
                            "resource": group_name,
                            "issue": "RDP port 3389 is open to the internet",
                            "severity": "CRITICAL",
                            "remediation": "Restrict RDP access to trusted IP addresses"
                        })

    return findings


if __name__ == "__main__":
    results = scan_security_groups()

    print("\n=== SECURITY GROUP SCAN ===")

    if not results:
        print("No security issues found.")
    else:
        for finding in results:
            print(f"\nService: {finding['service']}")
            print(f"Resource: {finding['resource']}")
            print(f"Issue: {finding['issue']}")
            print(f"Severity: {finding['severity']}")
            print(f"Remediation: {finding['remediation']}")