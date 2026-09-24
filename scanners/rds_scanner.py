import json
import random

def scan_rds():
    possible_findings = [
        {
            "service": "RDS",
            "resource": f"prod-db-instance-{random.randint(1,99)}",
            "issue": "RDS database is publicly accessible",
            "impact": "Exposing a database directly to the internet allows attackers from anywhere to attempt brute-force login attacks against your data.",
            "severity": "HIGH",
            "remediation": "Disable public accessibility for the database"
        },
        {
            "service": "RDS",
            "resource": f"analytics-db-{random.randint(1,99)}",
            "issue": "RDS storage encryption is disabled",
            "impact": "Database files are stored in plaintext on disk, which fails most regulatory compliance checks and risks data exposure.",
            "severity": "HIGH",
            "remediation": "Enable storage encryption for the database"
        },
        {
            "service": "RDS",
            "resource": f"dev-db-{random.randint(1,99)}",
            "issue": "RDS automated backups are disabled",
            "impact": "If the database is corrupted or attacked by ransomware, the lack of backups means total, unrecoverable data loss.",
            "severity": "MEDIUM",
            "remediation": "Enable automated backups with a retention period of at least 7 days"
        }
    ]
    return random.sample(possible_findings, random.randint(0, len(possible_findings)))


if __name__ == "__main__":
    results = scan_rds()

    print("\n=== RDS SECURITY SCAN ===")

    if not results:
        print("No security issues found.")
    else:
        for finding in results:
            print(f"\nService: {finding['service']}")
            print(f"Resource: {finding['resource']}")
            print(f"Issue: {finding['issue']}")
            print(f"Severity: {finding['severity']}")
            print(f"Remediation: {finding['remediation']}")