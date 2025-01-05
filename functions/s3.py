import boto3
import json
import time
import boto3.exceptions
from botocore.exceptions import ClientError, EndpointConnectionError
from concurrent.futures import ThreadPoolExecutor, as_completed


def bucket_check(s3_client, args):
    try:
        s3_client.get_bucket_policy(Bucket=args.bucket)
    except s3_client.exceptions.NoSuchBucket:
        print(
            'The bucket provided does not exist, or is not accessible by this user account.')
        quit()
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            print(f'IAM user account is missing the s3:GetBucketPolicy permission. Review the example policy in the repo and modify appropriately. Quitting...')
            quit()


def revert_bucket_policy(s3_client, bucket_resource, args):
    print('\nReverting UpdateAssumeRolePolicy policy back to default deny all...')
    revert_policy_document = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": {
        "AWS": "*"}, "Action": ["s3:DeleteObject", "s3:PutObject"], "Resource": bucket_resource}]}
    policy_document_str = json.dumps(revert_policy_document)
    try:
        s3_client.put_bucket_policy(
            Policy=policy_document_str, Bucket=args.bucket)
        print("Policy reverted successfully.")
    except Exception:
        print("Failed to revert policy. Update it manually in AWS console.")


def bucket_enum(args):
    bucket_resource = f"arn:aws:s3:::{args.bucket}/*"
    try:
        found_users = 0
        timeout = int(args.timeout) if args.timeout else 0
        print(
            f'Finding valid IAM usernames in {args.account} utilizing the S3 method.\nPlease be patient...\n')
        session = boto3.Session(
            aws_access_key_id=args.accesskey,
            aws_secret_access_key=args.secretkey
        )
        s3_client = session.client("s3")
        bucket_check(s3_client, args)

        def process_username(username):
            """Process a single username."""
            nonlocal found_users
            arn_val = f"arn:aws:iam::{args.account}:user/{username}"
            policy_document = {
                "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": {"AWS": arn_val}, "Action": ["s3:DeleteObject", "s3:PutObject"], "Resource": bucket_resource}]}
            policy_document_str = json.dumps(policy_document)
            try:
                if timeout:
                    time.sleep(timeout)
                enum_user = s3_client.put_bucket_policy(
                    Policy=policy_document_str,
                    Bucket=args.bucket,
                )
                if args.verbose:
                    print(enum_user)
                print(f"[+] Valid Username Found - {arn_val}")
                found_users += 1
            except ClientError as e:
                if e.response["Error"]["Code"] == "SignatureDoesNotMatch":
                    print(
                        '\nInvalid Signature. Access key and secret key may be incorrect.\nQuitting...')
                    raise KeyboardInterrupt
                if e.response["Error"]["Code"] == "AccessDenied":
                    print(
                        f'\nAccess denied for updating policy in {args.rolename}. Quitting...')
                    raise KeyboardInterrupt
                if e.response["Error"]["Code"] == "MalformedPolicyDocument":
                    pass  # This means the IAM user is not real.
                else:
                    pass
            except EndpointConnectionError:
                print("\nNetwork connection issue. Quitting...")
                raise KeyboardInterrupt
        with open(args.read) as possible_users:
            usernames = [line.strip() for line in possible_users]

        # Adjust max_workers as needed
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(
                process_username, username): username for username in usernames}
            try:
                for future in as_completed(futures):
                    future.result()  # Will raise exceptions from threads if any
            except KeyboardInterrupt:
                print(
                    "\nKeyboard interrupt detected. Stopping execution. This may take a minute.")
                # Cancel remaining threads
                executor.shutdown(wait=False)
                raise
        revert_bucket_policy(s3_client, bucket_resource, args)
        print(f"\n{found_users} valid IAM usernames found. Quitting...")

    except KeyboardInterrupt:
        print('\nOperation interrupted.')
        revert_bucket_policy(s3_client, bucket_resource, args)
