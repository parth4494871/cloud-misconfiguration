import boto3
from botocore.exceptions import ClientError

# THIS BLOCK IS CRITICAL - IT TELLS PYTHON TO USE LOCALSTACK
ENDPOINT = "http://localhost:4566"
CREDS = {
    "endpoint_url": ENDPOINT,
    "aws_access_key_id": "test",
    "aws_secret_access_key": "test",
    "region_name": "us-east-1"
}

def seed_s3():
    print("Seeding S3...")
    # Notice the **CREDS here, it tells boto3 to use LocalStack
    s3 = boto3.client('s3', **CREDS)
    bucket_name = "demo-public-bucket"
    try:
        s3.create_bucket(Bucket=bucket_name)
        s3.delete_public_access_block(Bucket=bucket_name)
        policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo-public-bucket/*"}]}'
        s3.put_bucket_policy(Bucket=bucket_name, Policy=policy)
        print(f"✅ Created public S3 bucket: {bucket_name}")
    except ClientError as e:
        print(f"⚠️ S3 Error: {e}")

def seed_iam():
    print("Seeding IAM...")
    iam = boto3.client('iam', **CREDS)
    user_name = "admin-user"
    try:
        iam.create_user(UserName=user_name)
        iam.attach_user_policy(UserName=user_name, PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        print(f"✅ Created IAM user with Admin access: {user_name}")
    except ClientError as e:
        print(f"⚠️ IAM Error: {e}")

def seed_ec2():
    print("Seeding Security Group...")
    ec2 = boto3.client('ec2', **CREDS)
    try:
        sg = ec2.create_security_group(GroupName="open-ssh-sg", Description="Misconfigured SSH access")
        ec2.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
        print(f"✅ Created open SSH Security Group: {sg['GroupId']}")
    except ClientError as e:
        print(f"⚠️ Security Group Error: {e}")

if __name__ == "__main__":
    print("🚀 Starting LocalStack seeding...")
    seed_s3()
    seed_iam()
    seed_ec2()
    print("🎉 Seeding complete!")