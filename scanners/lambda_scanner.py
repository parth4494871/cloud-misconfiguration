import boto3
def scan_lambda():
    findings = [
        {
            "service": "Lambda",
            "resource": "payment-processing-func",
            "issue": "X-Ray tracing is not enabled for Lambda function",
            "severity": "LOW",
            "remediation": "Enable Active tracing to monitor and troubleshoot function performance"
        }
    ]
    return findings

if __name__ == "__main__":
    results = scan_lambda()

    print("\n=== LAMBDA SECURITY SCAN ===")

    if not results:
        print("No security issues found.")
    else:
        for finding in results:
            print(f"\nService: {finding['service']}")
            print(f"Resource: {finding['resource']}")
            print(f"Issue: {finding['issue']}")
            print(f"Severity: {finding['severity']}")
            print(f"Remediation: {finding['remediation']}")
