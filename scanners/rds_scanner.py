import json


def scan_rds():
    findings = []

    with open("rds_data.json", "r") as file:
        data = json.load(file)

    for db in data["DBInstances"]:
        identifier = db["DBInstanceIdentifier"]

        if db.get("PubliclyAccessible", False):
            findings.append({
                "service": "RDS",
                "resource": identifier,
                "issue": "RDS database is publicly accessible",
                "severity": "HIGH",
                "remediation": "Disable public accessibility for the database"
            })

        if not db.get("StorageEncrypted", False):
            findings.append({
                "service": "RDS",
                "resource": identifier,
                "issue": "RDS storage encryption is disabled",
                "severity": "HIGH",
                "remediation": "Enable storage encryption for the database"
            })

    return findings


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