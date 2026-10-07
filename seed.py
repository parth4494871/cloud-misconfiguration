"""
seed.py — Populates LocalStack with sample misconfigurations for testing/demoing.

Creates:
  1. S3 bucket with Public ACL / policy
  2. IAM user without MFA and attached Admin policy
  3. Security Group opening port 22 (SSH) and 3389 (RDP) to 0.0.0.0/0
"""

import boto3
import json

ENDPOINT_URL = "http://localhost:4566"
REGION = "us-east-1"


def seed_localstack():
    print("🌱 Seeding LocalStack with misconfigurations for demo...")

    # 1. S3 Public Bucket
    try:
        s3 = boto3.client('s3', endpoint_url=ENDPOINT_URL, region_name=REGION,
                          aws_access_key_id='test', aws_secret_access_key='test')
        bucket_name = "vulnerable-company-logs-bucket"
        s3.create_bucket(Bucket=bucket_name)

        # Public Bucket Policy
        public_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }]
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))
        print("  [S3] Created public bucket:", bucket_name)
    except Exception as e:
        print("  [S3] Note:", e)

    # 2. Dangerous Security Group
    try:
        ec2 = boto3.client('ec2', endpoint_url=ENDPOINT_URL, region_name=REGION,
                           aws_access_key_id='test', aws_secret_access_key='test')
        sg = ec2.create_security_group(
            GroupName="launch-wizard-1-public",
            Description="Insecure open security group for demo"
        )
        sg_id = sg['GroupId']

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 3389,
                    'ToPort': 3389,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
        print("  [EC2] Created insecure security group opening ports 22 & 3389:", sg_id)
    except Exception as e:
        print("  [EC2] Note:", e)

    # 3. Insecure IAM User
    try:
        iam = boto3.client('iam', endpoint_url=ENDPOINT_URL, region_name=REGION,
                           aws_access_key_id='test', aws_secret_access_key='test')
        user_name = "contractor-dev"
        iam.create_user(UserName=user_name)
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        print("  [IAM] Created user 'contractor-dev' with AdministratorAccess policy and no MFA.")
    except Exception as e:
        print("  [IAM] Note:", e)

    print("✨ Seeding completed successfully!")


if __name__ == '__main__':
    seed_localstack()
