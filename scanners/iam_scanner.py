"""
iam_scanner.py — Scans IAM users for security misconfigurations.

Checks:
  1. No MFA — user has no multi-factor authentication enabled
  2. Old Access Keys — access keys older than 90 days
  3. AdministratorAccess — user has the overly-permissive admin policy attached
"""

from aws_connection import get_boto3_client
from datetime import datetime, timezone


def scan_iam():
    """
    Scan all IAM users and return a list of findings.
    """
    findings = []

    try:
        iam = get_boto3_client('iam')
        users = iam.list_users().get('Users', [])

        for user in users:
            username = user['UserName']

            # --- Check 1: No MFA ---
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username)
                if not mfa_devices.get('MFADevices', []):
                    findings.append({
                        'severity': 'HIGH',
                        'service': 'IAM',
                        'issue': 'User has no MFA enabled',
                        'resource': username,
                        'impact': 'Without MFA, a stolen password gives full access '
                                  'to this account.',
                        'remediation': 'Enable MFA for this user in the IAM console '
                                       'or using aws iam enable-mfa-device.'
                    })
            except Exception:
                pass

            # --- Check 2: Old Access Keys (>90 days) ---
            try:
                keys = iam.list_access_keys(UserName=username)
                for key in keys.get('AccessKeyMetadata', []):
                    create_date = key.get('CreateDate')
                    if create_date:
                        # Make sure both datetimes are timezone-aware
                        if create_date.tzinfo is None:
                            create_date = create_date.replace(tzinfo=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - create_date).days
                        if age_days > 90:
                            findings.append({
                                'severity': 'MEDIUM',
                                'service': 'IAM',
                                'issue': f'Access key is {age_days} days old',
                                'resource': f'{username} (Key: {key["AccessKeyId"]})',
                                'impact': 'Old access keys are more likely to be '
                                          'compromised. Rotate keys regularly.',
                                'remediation': 'Rotate the access key: create a new key, '
                                               'update your applications, then delete the old key.'
                            })
            except Exception:
                pass

            # --- Check 3: AdministratorAccess policy ---
            try:
                policies = iam.list_attached_user_policies(UserName=username)
                for policy in policies.get('AttachedPolicies', []):
                    if policy['PolicyName'] == 'AdministratorAccess':
                        findings.append({
                            'severity': 'CRITICAL',
                            'service': 'IAM',
                            'issue': 'User has AdministratorAccess policy',
                            'resource': username,
                            'impact': 'This user has unrestricted access to ALL AWS '
                                      'services. Follow the principle of least privilege.',
                            'remediation': 'Remove AdministratorAccess and attach only '
                                           'the specific policies this user needs.'
                        })
            except Exception:
                pass

    except Exception as e:
        findings.append({
            'severity': 'LOW',
            'service': 'IAM',
            'issue': f'Could not scan IAM: {str(e)}',
            'resource': 'N/A',
            'impact': 'IAM scan was skipped.',
            'remediation': 'Check AWS connection and permissions.'
        })

    return findings
