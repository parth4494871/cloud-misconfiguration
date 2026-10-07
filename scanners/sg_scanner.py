"""
sg_scanner.py — Scans Security Groups for dangerous open ports.

Checks for inbound rules that allow traffic from 0.0.0.0/0 (anywhere)
on sensitive ports:
  - Port 22 (SSH) — remote server access
  - Port 3389 (RDP) — remote desktop
  - Port 3306 (MySQL) — database
  - Port 5432 (PostgreSQL) — database
  - Port 0 (All traffic) — everything open
"""

from aws_connection import get_boto3_client


# Ports we consider dangerous when open to the internet
DANGEROUS_PORTS = {
    22: ('SSH', 'CRITICAL'),
    3389: ('RDP', 'CRITICAL'),
    3306: ('MySQL', 'HIGH'),
    5432: ('PostgreSQL', 'HIGH'),
    0: ('All Traffic', 'CRITICAL'),
}


def scan_security_groups():
    """
    Scan all EC2 security groups for dangerous inbound rules.
    """
    findings = []

    try:
        ec2 = get_boto3_client('ec2')
        groups = ec2.describe_security_groups().get('SecurityGroups', [])

        for sg in groups:
            sg_id = sg.get('GroupId', 'Unknown')
            sg_name = sg.get('GroupName', 'Unknown')

            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                ip_protocol = rule.get('IpProtocol', '')

                # Check each IP range in this rule
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')

                    # 0.0.0.0/0 means "open to the entire internet"
                    if cidr == '0.0.0.0/0':
                        # Protocol -1 means ALL traffic
                        if ip_protocol == '-1':
                            findings.append({
                                'severity': 'CRITICAL',
                                'service': 'Security Groups',
                                'issue': 'All traffic open to 0.0.0.0/0',
                                'resource': f'{sg_name} ({sg_id})',
                                'impact': 'Every port on every protocol is accessible '
                                          'from the internet. This is extremely dangerous.',
                                'remediation': 'Restrict the security group to only the '
                                               'ports and IP ranges you actually need.'
                            })
                        else:
                            # Check if any dangerous port falls in the range
                            for port, (service, severity) in DANGEROUS_PORTS.items():
                                if port == 0:
                                    continue  # Handled by protocol -1 above
                                if from_port <= port <= to_port:
                                    findings.append({
                                        'severity': severity,
                                        'service': 'Security Groups',
                                        'issue': f'Port {port} ({service}) open to 0.0.0.0/0',
                                        'resource': f'{sg_name} ({sg_id})',
                                        'impact': f'{service} (port {port}) is accessible from '
                                                  'anywhere on the internet. Attackers can '
                                                  'attempt brute-force or exploit vulnerabilities.',
                                        'remediation': f'Restrict port {port} to specific IP '
                                                       'addresses only (e.g., your office IP).'
                                    })

    except Exception as e:
        findings.append({
            'severity': 'LOW',
            'service': 'Security Groups',
            'issue': f'Could not scan Security Groups: {str(e)}',
            'resource': 'N/A',
            'impact': 'Security Groups scan was skipped.',
            'remediation': 'Check AWS connection and permissions.'
        })

    return findings
