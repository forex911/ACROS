import os
import logging
from typing import Optional
import json

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from app.core.config import S3_ENDPOINT, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET, S3_USE_SSL, S3_PRESIGNED_EXPIRATION

logger = logging.getLogger("object_store")


def s3_client():
    client_kwargs = {
        'region_name': S3_REGION,
        'aws_access_key_id': S3_ACCESS_KEY,
        'aws_secret_access_key': S3_SECRET_KEY,
        'use_ssl': S3_USE_SSL,
        'config': Config(signature_version='s3v4')
    }
    if S3_ENDPOINT:
        client_kwargs['endpoint_url'] = S3_ENDPOINT

    client = boto3.client('s3', **client_kwargs)
    return client

def init_s3_lifecycle():
    """
    Initializes immutable storage rules and lifecycle policies on MinIO/S3.
    """
    client = s3_client()
    try:
        # Create bucket if not exists
        try:
            client.head_bucket(Bucket=S3_BUCKET)
        except ClientError:
            client.create_bucket(Bucket=S3_BUCKET)
            logger.info(f"Created bucket {S3_BUCKET}")
            
        # Enable object lock for immutability
        try:
            client.put_object_lock_configuration(
                Bucket=S3_BUCKET,
                ObjectLockConfiguration={
                    'ObjectLockEnabled': 'Enabled',
                    'Rule': {
                        'DefaultRetention': {
                            'Mode': 'COMPLIANCE',
                            'Days': 90
                        }
                    }
                }
            )
            logger.info(f"Enabled Object Lock (Immutability) on {S3_BUCKET}")
        except Exception as e:
            logger.warning(f"Failed to set Object Lock: {e}")
            
        # Set Lifecycle policy for 90-day deletion
        lifecycle_config = {
            'Rules': [
                {
                    'ID': 'DeleteOldArtifacts',
                    'Filter': {'Prefix': ''},
                    'Status': 'Enabled',
                    'Expiration': {
                        'Days': 90
                    }
                }
            ]
        }
        client.put_bucket_lifecycle_configuration(
            Bucket=S3_BUCKET,
            LifecycleConfiguration=lifecycle_config
        )
        logger.info(f"Set 90-day lifecycle expiration on {S3_BUCKET}")
        
    except Exception as e:
        logger.error(f"Failed to initialize S3 lifecycle rules: {e}")

def upload_file(local_path: str, bucket: Optional[str] = None, key: Optional[str] = None) -> dict:
    if not bucket:
        bucket = S3_BUCKET
    if not key:
        key = os.path.basename(local_path)

    client = s3_client()
    size = os.path.getsize(local_path)

    with open(local_path, 'rb') as fh:
        client.upload_fileobj(fh, bucket, key)

    return {'bucket': bucket, 'key': key, 'size': size}


def generate_presigned_url(bucket: Optional[str], key: str, expires: Optional[int] = None) -> str:
    if expires is None:
        expires = S3_PRESIGNED_EXPIRATION
    client = s3_client()
    url = client.generate_presigned_url('get_object', Params={'Bucket': bucket, 'Key': key}, ExpiresIn=expires)
    return url
