"""
seed.py — Populates LocalStack / AWS with sample misconfigurations across all services.

Creates intentional security vulnerabilities for live demoing:
  1. S3: Public bucket with public read policy and unversioned bucket
  2. IAM: User with AdministratorAccess policy, no MFA, and old access key
  3. Security Group: Inbound rules exposing SSH (22), RDP (3389), MySQL (3306), and PostgreSQL (5432) to 0.0.0.0/0
  4. RDS: Publicly accessible database instance without storage encryption and disabled backups
  5. CloudTrail: Unencrypted/single-region trail setup simulation
"""

import boto3
import json
import os
from aws_connection import get_aws_config

def get_client(service_name):
    config = get_aws_config()
    kwargs = {
        'aws_access_key_id': config.get('aws_access_key', 'test'),
        'aws_secret_access_key': config.get('aws_secret_key', 'test'),
        'region_name': config.get('region', 'us-east-1'),
    }
    if config.get('mode') == 'localstack':
        kwargs['endpoint_url'] = config.get('endpoint_url', 'http://localhost:4566')

    return boto3.client(service_name, **kwargs)

def seed_environment():
    config = get_aws_config()
    target = config.get('mode', 'localstack').upper()
    print(f"🌱 Seeding {target} environment with intentional misconfigurations for demo...\n")

    # --- 1. S3 Misconfigurations ---
    try:
        s3 = get_client('s3')
        bucket_name = "vulnerable-company-logs-bucket"

        # Create bucket
        try:
            s3.create_bucket(Bucket=bucket_name)
        except Exception:
            pass

        # Disable Block Public Access
        try:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': False,
                    'IgnorePublicAcls': False,
                    'BlockPublicPolicy': False,
                    'RestrictPublicBuckets': False
                }
            )
        except Exception:
            pass

        # Attach Public Policy
        public_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }]
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))
        print(f"  ✅ [S3] Created public bucket '{bucket_name}' with public policy & versioning disabled.")
    except Exception as e:
        print(f"  ⚠️ [S3] Could not seed S3: {e}")

    # --- 2. Security Group Misconfigurations ---
    try:
        ec2 = get_client('ec2')
        sg_name = "demo-insecure-sg"

        # Check if SG exists
        vpcs = ec2.describe_vpcs().get('Vpcs', [])
        vpc_id = vpcs[0]['VpcId'] if vpcs else None

        sg_id = None
        existing_sgs = ec2.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
        ).get('SecurityGroups', [])

        if existing_sgs:
            sg_id = existing_sgs[0]['GroupId']
        else:
            kwargs = {'GroupName': sg_name, 'Description': 'Demo Security Group open to the world'}
            if vpc_id:
                kwargs['VpcId'] = vpc_id
            res = ec2.create_security_group(**kwargs)
            sg_id = res['GroupId']

        # Authorize dangerous inbound ports from 0.0.0.0/0
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 3389, 'ToPort': 3389, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ]
        )
        print(f"  ✅ [EC2] Created Security Group '{sg_name}' ({sg_id}) exposing SSH (22), RDP (3389), MySQL (3306), Postgres (5432) to 0.0.0.0/0.")
    except Exception as e:
        print(f"  ⚠️ [EC2] Could not seed Security Group: {e}")

    # --- 3. IAM Misconfigurations ---
    try:
        iam = get_client('iam')
        user_name = "contractor-dev-admin"

        try:
            iam.create_user(UserName=user_name)
        except Exception:
            pass

        # Attach AdministratorAccess policy
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )

        # Create access key
        try:
            iam.create_access_key(UserName=user_name)
        except Exception:
            pass

        print(f"  ✅ [IAM] Created user '{user_name}' with AdministratorAccess policy, active key, and NO MFA.")
    except Exception as e:
        print(f"  ⚠️ [IAM] Could not seed IAM user: {e}")

    # --- 4. RDS Misconfigurations ---
    try:
        rds = get_client('rds')
        db_id = "vulnerable-prod-db"

        rds.create_db_instance(
            DBInstanceIdentifier=db_id,
            AllocatedStorage=5,
            DBInstanceClass='db.t3.micro',
            Engine='mysql',
            MasterUsername='admin',
            MasterUserPassword='Password123!',
            PubliclyAccessible=True,
            StorageEncrypted=False,
            BackupRetentionPeriod=0
        )
        print(f"  ✅ [RDS] Created DB instance '{db_id}' with PubliclyAccessible=True, StorageEncrypted=False, BackupRetentionPeriod=0.")
    except Exception as e:
        print(f"  ℹ️ [RDS] Note (RDS requires LocalStack Pro or AWS Cloud): {e}")

    print("\n✨ Seeding completed! You can now run a Security Scan from the dashboard.")

if __name__ == '__main__':
    seed_environment()
