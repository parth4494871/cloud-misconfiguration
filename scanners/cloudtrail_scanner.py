"""
cloudtrail_scanner.py — Scans CloudTrail for logging misconfigurations.

Checks:
  1. Logging Disabled — no trails exist or trail is not logging
  2. No Log File Validation — logs could be tampered with
  3. Not Multi-Region — only logging events in one region

NOTE: CloudTrail may not work in LocalStack free tier. If it fails,
the scanner returns a LOW-severity notice and continues gracefully.
"""

from aws_connection import get_boto3_client


def scan_cloudtrail():
    """
    Scan CloudTrail configuration and return a list of findings.
    """
    findings = []

    try:
        ct = get_boto3_client('cloudtrail')
        trails = ct.describe_trails().get('trailList', [])

        # --- Check: No trails exist at all ---
        if not trails:
            findings.append({
                'severity': 'CRITICAL',
                'service': 'CloudTrail',
                'issue': 'No CloudTrail trails configured',
                'resource': 'Account-wide',
                'impact': 'Without CloudTrail, there is no audit log of API calls. '
                          'Security incidents cannot be investigated.',
                'remediation': 'Create a CloudTrail trail: aws cloudtrail create-trail '
                               '--name my-trail --s3-bucket-name my-log-bucket'
            })
            return findings

        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')

            # --- Check logging status ---
            try:
                status = ct.get_trail_status(Name=trail_name)
                if not status.get('IsLogging', False):
                    findings.append({
                        'severity': 'CRITICAL',
                        'service': 'CloudTrail',
                        'issue': 'CloudTrail logging is disabled',
                        'resource': trail_name,
                        'impact': 'The trail exists but is not recording events. '
                                  'All API activity is going unlogged.',
                        'remediation': 'Start logging: aws cloudtrail start-logging '
                                       f'--name {trail_name}'
                    })
            except Exception:
                pass

            # --- Check 2: No Log File Validation ---
            if not trail.get('LogFileValidationEnabled', False):
                findings.append({
                    'severity': 'MEDIUM',
                    'service': 'CloudTrail',
                    'issue': 'Log file validation is disabled',
                    'resource': trail_name,
                    'impact': 'Without validation, log files could be modified or '
                              'deleted by an attacker without detection.',
                    'remediation': 'Enable log validation: aws cloudtrail update-trail '
                                   f'--name {trail_name} --enable-log-file-validation'
                })

            # --- Check 3: Not Multi-Region ---
            if not trail.get('IsMultiRegionTrail', False):
                findings.append({
                    'severity': 'MEDIUM',
                    'service': 'CloudTrail',
                    'issue': 'Trail is not multi-region',
                    'resource': trail_name,
                    'impact': 'Events in other AWS regions are not being logged. '
                              'An attacker could operate in an unmonitored region.',
                    'remediation': 'Enable multi-region: aws cloudtrail update-trail '
                                   f'--name {trail_name} --is-multi-region-trail'
                })

    except Exception as e:
        error_msg = str(e)
        if 'Could not connect' in error_msg or 'endpoint' in error_msg.lower():
            findings.append({
                'severity': 'LOW',
                'service': 'CloudTrail',
                'issue': 'CloudTrail service not available (LocalStack free tier limitation)',
                'resource': 'N/A',
                'impact': 'CloudTrail scan was skipped — this service may not be '
                          'available in your LocalStack version.',
                'remediation': 'Use LocalStack Pro for CloudTrail support, or test with real AWS.'
            })
        else:
            findings.append({
                'severity': 'LOW',
                'service': 'CloudTrail',
                'issue': f'Could not scan CloudTrail: {error_msg}',
                'resource': 'N/A',
                'impact': 'CloudTrail scan was skipped.',
                'remediation': 'Check AWS connection and permissions.'
            })

    return findings
