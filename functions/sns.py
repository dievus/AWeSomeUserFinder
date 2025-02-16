import boto3
import json
import time
import boto3.exceptions
import random
import string
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    ParamValidationError,
)
from concurrent.futures import ThreadPoolExecutor, as_completed


def revert_to_default_policy(args, sns_client, account_id):
    try:
        default_policy = {
            "Version": "2008-10-17",
            "Id": "__default_policy_ID",
            "Statement": [
                {
                    "Sid": "__default_statement_ID",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "SNS:Publish",
                        "SNS:RemovePermission",
                        "SNS:SetTopicAttributes",
                        "SNS:DeleteTopic",
                        "SNS:ListSubscriptionsByTopic",
                        "SNS:GetTopicAttributes",
                        "SNS:AddPermission",
                        "SNS:Subscribe"
                    ],
                    "Resource": f"{args.topicarn}",
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceOwner": f"{account_id}"
                                    }
                    }
                }
            ]
        }
        # try:
        new_policy = json.dumps(default_policy)
        sns_client.set_topic_attributes(
            TopicArn=args.topicarn,
            AttributeName='Policy',
            AttributeValue=new_policy
        )

        print(
            f"Policy reverted successfully.")

    except Exception as e:
        print(f"Failed to revert policy. Update it manually in AWS console.")


def confirm_credentials(args, sns_client, sts_client):
    try:
        sts_response = sts_client.get_caller_identity()
        account_id = sts_response['Account']
        confirm_topic(args, sns_client, account_id)
    except Exception as e:
        if e.response["Error"]["Code"] == "SignatureDoesNotMatch":
            print(
                "\nInvalid Signature. Access key and secret key may be incorrect.\nQuitting..."
            )
            quit()
        else:
            print(f"\nSome issue occurred: {e}.\nQuitting...")
            quit()


def confirm_topic(args, sns_client, account_id):
    try:
        topic_check = sns_client.get_topic_attributes(
            TopicArn=args.topicarn
        )
        if topic_check:
            sns_enum(args, sns_client, account_id)
    except Exception as e:
        if e.response['Error']['Code'] == 'NotFound' in str(e):
            print('Topic does not exist. Quitting...')
            quit()
        if e.response['Error']['Code'] == 'InvalidParameter' in str(e):
            if args.region:
                print('The region for SNS is likely incorrect. Check and try again.')
                quit()
            else:
                print('Region is likely missing. Include a region and try again.')
                quit()
        if e.response['Error']['Code'] == 'InvalidClientTokenId' in str(e):
            print('Invalid account. Quitting...')
            quit()
        if e.response["Error"]["Code"] == "SignatureDoesNotMatch":
            print(
                "\nInvalid Signature. Access key and secret key may be incorrect.\nQuitting..."
            )
            quit()
        else:
            print(f"\nSome issue occurred: {e}.\nQuitting...")
            quit()


def sns_enum(args, sns_client, account_id):
    found_users = 0
    try:
        timeout = int(args.timeout) if args.timeout else 0

        def process_username(username):
            nonlocal found_users
            arn_val = f"arn:aws:iam::{args.account}:user/{username}"
            # Create a new statement for the principal
            default_policy = {
                "Version": "2008-10-17",
                "Id": "__default_policy_ID",
                "Statement": [
                    {
                        "Sid": "__default_statement_ID",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": [
                            "SNS:Publish",
                            "SNS:RemovePermission",
                            "SNS:SetTopicAttributes",
                            "SNS:DeleteTopic",
                            "SNS:ListSubscriptionsByTopic",
                            "SNS:GetTopicAttributes",
                            "SNS:AddPermission",
                            "SNS:Subscribe"
                        ],
                        "Resource": args.topicarn,
                        "Condition": {
                            "StringEquals": {
                                "AWS:SourceOwner": account_id
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": arn_val
                        },
                        "Action": "sns:Subscribe",
                        "Resource": args.topicarn
                    }
                ]
            }
            policy_document_str = json.dumps(default_policy)
            try:
                if timeout:
                    time.sleep(timeout)
                enum_user = sns_client.set_topic_attributes(
                    TopicArn=args.topicarn,
                    AttributeName='Policy',
                    AttributeValue=policy_document_str
                )
                if args.verbose:
                    print(enum_user)
                print(f"[+] Valid Username Found - {arn_val}")
                found_users += 1
            except ClientError as e:
                if e.response["Error"]["Code"] == "SignatureDoesNotMatch":
                    print(
                        "\nInvalid Signature. Access key and secret key may be incorrect.\nQuitting..."
                    )
                    raise KeyboardInterrupt
                if e.response["Error"]["Code"] == "AccessDenied":
                    print(
                        f"\nAccess denied for updating policy in {args.rolename}. Quitting..."
                    )
                    raise KeyboardInterrupt
                if e.response["Error"]["Code"] == "MalformedPolicyDocument":
                    revert_to_default_policy(
                        args, sns_client, default_policy, account_id)
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
            futures = {
                executor.submit(process_username, username): username
                for username in usernames
            }
            try:
                for future in as_completed(futures):
                    future.result()  # Will raise exceptions from threads if any
            except KeyboardInterrupt:
                print(
                    "\nKeyboard interrupt detected. Stopping execution. This may take a minute."
                )
                # Cancel remaining threads
                executor.shutdown(wait=False)
                raise
        revert_to_default_policy(args, sns_client, account_id)
        print(f"\n{found_users} valid IAM usernames found. Quitting...")
    except Exception as e:
        print(e)
        if e.resposne['Error']['Code'] == 'InvalidParameter' in str(e):
            if args.region:
                print('The region for SNS is likely incorrect. Check and try again.')
                quit()
            else:
                print('Region is likely missing. Include a region and try again.')
                quit()


def sns_handler(args):
    print(
        f"Finding valid IAM usernames in {args.account} utilizing the SNS policy method.\nPlease be patient...\n"
    )
    session = boto3.Session(
        aws_access_key_id=args.accesskey, aws_secret_access_key=args.secretkey
    )
    sns_client = session.client("sns", region_name=args.region)
    sts_client = session.client("sts")
    confirm_credentials(args, sns_client, sts_client)
