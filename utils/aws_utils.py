"""
Utils script containing functions for AWS ops
"""
import json
import os

import logging as log

import boto3
from botocore.exceptions import ClientError


def publish_message(phone_number, message):
    """
    Create an SNS client and publishes message
    """
    sns = boto3.client("sns", region_name="ap-southeast-1")
    response = sns.publish(
        PhoneNumber=phone_number,
        Message=message,
        MessageAttributes={
            'AWS.SNS.SMS.SenderID': {'DataType': 'String', 'StringValue': 'SENDERID'},
            'AWS.SNS.SMS.SMSType': {'DataType': 'String', 'StringValue': 'Transactional'},
        },
    )


def download_file_from_s3(
    bucket_name,
    local_path_to_save_file,
    file_path_in_bucket,
):
    try:
        s3 = boto3.client("s3")
        s3.download_file(bucket_name, file_path_in_bucket, local_path_to_save_file)
    except ClientError:
        raise FileNotFoundError


def check_file_existence_in_s3(bucket_name, file_path_in_bucket):
    try:
        s3 = boto3.resource("s3")
        s3.Object(bucket_name, file_path_in_bucket).load()
    except ClientError:
        pass
    else:
        raise FileExistsError


def file_exists_in_s3(bucket_name, file_path):
    s3 = boto3.resource('s3')
    try:
        s3.Object(bucket_name, file_path).load()
    except ClientError as e:
        if e.response['Error']['Code'] == "404":
            return False
        else:
            # Something else has gone wrong.
            raise
    else:
        return True


def upload_file_to_s3(local_file_full_path, bucket_name, bucket_file_full_path):
    retry_count = 0
    uploaded = False
    while not uploaded:
        try:
            s3 = boto3.client('s3')
            s3.upload_file(local_file_full_path, bucket_name, bucket_file_full_path)
            uploaded = True
        except ClientError:
            if retry_count >= 5:
                # if bucket upload fails then on retrying
                # this whole new request should not give file exist error.
                os.remove(f"{local_file_full_path}")
                raise InterruptedError
        finally:
            retry_count = retry_count + 1


def upload_file_buffer_to_s3(file_buffer, bucket_name, bucket_file_full_path):
    retry_count = 0
    uploaded = False
    while not uploaded:
        try:
            s3 = boto3.client('s3')
            s3.put_object(Body=file_buffer, Bucket=bucket_name, Key=bucket_file_full_path)
            uploaded = True
        except ClientError:
            if retry_count >= 5:
                raise InterruptedError
        finally:
            retry_count = retry_count + 1


def fetch_s3_object_url(bucket_name, bucket_file_full_path, prefix='/', delimiter='/'):
    region = boto3.client('s3')
    region = region.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
    obj_url = f"https://s3-{region}.amazonaws.com/{bucket_name}/{bucket_file_full_path}"

    return obj_url


def delete_s3_object(bucket_name, bucket_file_full_path):
    s3 = boto3.client('s3')
    s3.delete_object(Bucket=bucket_name, Key=bucket_file_full_path)


def rename_s3_object(content_id, new_filename, old_filename, file_format, new_file_format=None):
    """
    Rename s3 object
    """
    from config import ConfigVariable

    if new_file_format is None:
        new_file_format = file_format
    s3 = boto3.resource("s3")
    s3.Object(
        ConfigVariable.BUCKET_NAME,
        f"{ConfigVariable.BUCKET_PATH}/{content_id}/{new_filename}.{new_file_format}",
    ).copy_from(CopySource=f"{ConfigVariable.BUCKET_NAME}/{ConfigVariable.BUCKET_PATH}/{content_id}/{old_filename}.{file_format}")
    s3.Object(ConfigVariable.BUCKET_NAME, f"{ConfigVariable.BUCKET_PATH}/{content_id}/{old_filename}.{file_format}").delete()


def get_secret(secret_id, region):
    client = boto3.client('secretsmanager', region_name=region)
    secret_ = client.get_secret_value(SecretId=secret_id)
    return json.loads(secret_.get('SecretString'))