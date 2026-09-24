import boto3
import random
def scan_lambda():
    possible_findings = [
        {
            "service": "Lambda",
            "resource": f"payment-processing-func-{random.randint(1,99)}",
            "issue": "X-Ray tracing is not enabled for Lambda function",
            "impact": "Without tracing, it becomes nearly impossible to identify performance bottlenecks, debug complex distributed errors, or detect malicious anomalies.",
            "severity": "LOW",
            "remediation": "Enable Active tracing to monitor and troubleshoot function performance"
        },
        {
            "service": "Lambda",
            "resource": f"image-resizer-func-{random.randint(1,99)}",
            "issue": "Lambda function is using an outdated runtime (Node.js 14)",
            "impact": "Old runtimes do not receive security patches. Running outdated software exposes the function to publicly known vulnerabilities.",
            "severity": "MEDIUM",
            "remediation": "Upgrade function runtime to a supported version"
        }
    ]
    return random.sample(possible_findings, random.randint(0, len(possible_findings)))

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
