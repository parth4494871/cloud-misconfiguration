"""
s3_scanner.py — Scans S3 buckets for security misconfigurations.

Checks:
  1. Public ACL — bucket allows public read/write via ACL
  2. Public Bucket Policy — bucket policy grants access to everyone ("*")
  3. Versioning Disabled — no version history means no recovery from deletions
"""

from aws_connection import get_boto3_client
import json


def scan_s3():
    """
    Scan all S3 buckets and return a list of findings.
    Each finding is a dict with: severity, service, issue, resource,
    impact, and remediation.
    """
    findings = []

    try:
        s3 = get_boto3_client('s3')
        buckets = s3.list_buckets().get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']

            # --- Check 1: Public ACL ---
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI', '')
                    # This URI means "everyone on the internet"
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        findings.append({
                            'severity': 'CRITICAL',
                            'service': 'S3',
                            'issue': 'Bucket has public ACL',
                            'resource': bucket_name,
                            'impact': 'Anyone on the internet can access this bucket. '
                                      'Sensitive data could be exposed.',
                            'remediation': 'Remove public ACL grants. Use '
                                           'aws s3api put-bucket-acl --bucket '
                                           f'{bucket_name} --acl private'
                        })
                        break  # One finding per bucket is enough
            except Exception:
                pass  # ACL check not supported or access denied

            # --- Check 2: Public Bucket Policy ---
            try:
                policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
                policy = json.loads(policy_str)
                for statement in policy.get('Statement', []):
                    principal = statement.get('Principal', '')
                    effect = statement.get('Effect', '')
                    # Principal "*" means anyone
                    if principal == '*' and effect == 'Allow':
                        findings.append({
                            'severity': 'CRITICAL',
                            'service': 'S3',
                            'issue': 'Bucket policy allows public access',
                            'resource': bucket_name,
                            'impact': 'The bucket policy grants access to all users (*). '
                                      'Data could be read or modified by anyone.',
                            'remediation': 'Remove the public policy statement. Use '
                                           'aws s3api delete-bucket-policy --bucket '
                                           f'{bucket_name}'
                        })
                        break
            except s3.exceptions.from_code('NoSuchBucketPolicy'):
                pass  # No policy = not public (good)
            except Exception:
                pass

            # --- Check 3: Versioning Disabled ---
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                status = versioning.get('Status', 'Disabled')
                if status != 'Enabled':
                    findings.append({
                        'severity': 'MEDIUM',
                        'service': 'S3',
                        'issue': 'Bucket versioning is disabled',
                        'resource': bucket_name,
                        'impact': 'Without versioning, deleted or overwritten files '
                                  'cannot be recovered.',
                        'remediation': 'Enable versioning: aws s3api put-bucket-versioning '
                                       f'--bucket {bucket_name} '
                                       '--versioning-configuration Status=Enabled'
                    })
            except Exception:
                pass

    except Exception as e:
        findings.append({
            'severity': 'LOW',
            'service': 'S3',
            'issue': f'Could not scan S3: {str(e)}',
            'resource': 'N/A',
            'impact': 'S3 scan was skipped.',
            'remediation': 'Check AWS connection and permissions.'
        })

    return findings
