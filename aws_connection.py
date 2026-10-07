"""
aws_connection.py — AWS/LocalStack connection management.

This module:
  1. Stores the AWS connection settings (endpoint, keys, region)
  2. Validates the connection by calling list_buckets()
  3. Creates boto3 clients for each AWS service the scanners need
"""

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError


# Global variable to store the current AWS connection settings.
# Set when the user submits the connection form.
_aws_config = {
    'endpoint_url': 'http://localhost:4566',   # LocalStack default
    'aws_access_key_id': 'test',               # LocalStack default
    'aws_secret_access_key': 'test',           # LocalStack default
    'region_name': 'us-east-1'
}


def set_aws_config(endpoint_url, access_key, secret_key, region):
    """
    Save the AWS connection settings entered by the user.
    Called when the user submits the connection form.
    """
    global _aws_config
    _aws_config = {
        'endpoint_url': endpoint_url.rstrip('/'),
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
    }


def get_aws_config():
    """Return the current AWS connection settings."""
    return _aws_config.copy()


def get_boto3_client(service_name):
    """
    Create a boto3 client for the given AWS service (e.g. 's3', 'iam', 'ec2').
    Uses the connection settings from set_aws_config().
    """
    return boto3.client(
        service_name,
        endpoint_url=_aws_config['endpoint_url'],
        aws_access_key_id=_aws_config['aws_access_key_id'],
        aws_secret_access_key=_aws_config['aws_secret_access_key'],
        region_name=_aws_config['region_name']
    )


def validate_connection():
    """
    Test the AWS connection by calling S3's list_buckets().
    Returns (True, "Connected successfully") or (False, "error message").
    """
    try:
        s3 = get_boto3_client('s3')
        s3.list_buckets()
        return True, "Connected successfully to AWS/LocalStack!"
    except EndpointConnectionError:
        return False, "Cannot reach the endpoint. Is LocalStack running?"
    except NoCredentialsError:
        return False, "Invalid credentials. Check your access key and secret key."
    except ClientError as e:
        return False, f"AWS error: {e.response['Error']['Message']}"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"
