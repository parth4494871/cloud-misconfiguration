"""
rds_scanner.py — Scans RDS database instances for misconfigurations.

Checks:
  1. Publicly Accessible — RDS instance reachable from the internet
  2. No Encryption — data at rest is not encrypted
  3. No Automated Backups — backup retention is 0 days

NOTE: RDS may not work in LocalStack free tier. If it fails,
the scanner returns a LOW-severity notice and continues gracefully.
"""

from aws_connection import get_boto3_client


def scan_rds():
    """
    Scan all RDS instances and return a list of findings.
    """
    findings = []

    try:
        rds = get_boto3_client('rds')
        instances = rds.describe_db_instances().get('DBInstances', [])

        for db in instances:
            db_id = db.get('DBInstanceIdentifier', 'Unknown')

            # --- Check 1: Publicly Accessible ---
            if db.get('PubliclyAccessible', False):
                findings.append({
                    'severity': 'CRITICAL',
                    'service': 'RDS',
                    'issue': 'Database is publicly accessible',
                    'resource': db_id,
                    'impact': 'The database can be reached from the internet. '
                              'Attackers can attempt to connect and steal data.',
                    'remediation': 'Modify the DB instance to set PubliclyAccessible=false. '
                                   'Use: aws rds modify-db-instance '
                                   f'--db-instance-identifier {db_id} '
                                   '--no-publicly-accessible'
                })

            # --- Check 2: No Encryption ---
            if not db.get('StorageEncrypted', False):
                findings.append({
                    'severity': 'HIGH',
                    'service': 'RDS',
                    'issue': 'Database storage is not encrypted',
                    'resource': db_id,
                    'impact': 'Data stored on disk is not encrypted. If the '
                              'storage is compromised, data is readable in plain text.',
                    'remediation': 'Enable encryption at rest. Note: you cannot encrypt '
                                   'an existing unencrypted DB — you must create an '
                                   'encrypted snapshot and restore from it.'
                })

            # --- Check 3: No Automated Backups ---
            retention = db.get('BackupRetentionPeriod', 0)
            if retention == 0:
                findings.append({
                    'severity': 'HIGH',
                    'service': 'RDS',
                    'issue': 'Automated backups are disabled',
                    'resource': db_id,
                    'impact': 'If the database is deleted or corrupted, there is '
                              'no backup to restore from.',
                    'remediation': 'Enable automated backups with at least 7 days retention: '
                                   'aws rds modify-db-instance '
                                   f'--db-instance-identifier {db_id} '
                                   '--backup-retention-period 7'
                })

        # If no instances found at all, that's fine — not a finding
        if not instances:
            pass

    except Exception as e:
        # RDS may not be available in LocalStack free tier
        error_msg = str(e)
        if 'Could not connect' in error_msg or 'endpoint' in error_msg.lower():
            findings.append({
                'severity': 'LOW',
                'service': 'RDS',
                'issue': 'RDS service not available (LocalStack free tier limitation)',
                'resource': 'N/A',
                'impact': 'RDS scan was skipped — this service may not be '
                          'available in your LocalStack version.',
                'remediation': 'Use LocalStack Pro for RDS support, or test with real AWS.'
            })
        else:
            findings.append({
                'severity': 'LOW',
                'service': 'RDS',
                'issue': f'Could not scan RDS: {error_msg}',
                'resource': 'N/A',
                'impact': 'RDS scan was skipped.',
                'remediation': 'Check AWS connection and permissions.'
            })

    return findings
