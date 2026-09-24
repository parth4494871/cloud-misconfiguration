import boto3


def scan_iam():
    iam = boto3.client(
        "iam",
        endpoint_url="http://localhost:4566",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test"
    )

    findings = []

    response = iam.list_users()

    for user in response["Users"]:
        username = user["UserName"]

        try:
            mfa = iam.list_mfa_devices(UserName=username)

            if len(mfa["MFADevices"]) == 0:
                findings.append({
                    "service": "IAM",
                    "resource": username,
                    "issue": "IAM user does not have MFA enabled",
                    "severity": "HIGH",
                    "remediation": "Enable MFA for the IAM user"
                })

        except Exception as e:
            findings.append({
                "service": "IAM",
                "resource": username,
                "issue": f"Unable to check MFA: {e}",
                "severity": "LOW",
                "remediation": "Check IAM user configuration"
            })

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