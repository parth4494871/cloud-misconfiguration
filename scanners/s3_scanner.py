import boto3


def scan_s3():
    s3 = boto3.client(
        "s3",
        endpoint_url="http://localhost:4566",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test"
    )

    findings = []

    response = s3.list_buckets()

    for bucket in response["Buckets"]:
        bucket_name = bucket["Name"]

        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)

            is_public = False

            for grant in acl["Grants"]:
                grantee = grant.get("Grantee", {})

                if (
                    grantee.get("Type") == "Group"
                    and "AllUsers" in grantee.get("URI", "")
                ):
                    is_public = True

            if is_public:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "issue": "S3 bucket is publicly accessible",
                    "severity": "CRITICAL",
                    "remediation": "Block public access to the S3 bucket"
                })

        except Exception as e:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "issue": f"Unable to check bucket: {e}",
                "severity": "LOW",
                "remediation": "Check the bucket configuration"
            })

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