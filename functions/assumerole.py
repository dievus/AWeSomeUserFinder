import boto3
import json
import time
import boto3.exceptions
# testing
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    ParamValidationError,
)
from concurrent.futures import ThreadPoolExecutor, as_completed


def permissions_check(iam_client, args):
    try:
        iam_client.get_role(RoleName=args.rolename)
    except iam_client.exceptions.NoSuchEntityException:
        print(
            "The role provided is not valid. Either provide a valid role, or generate one with updateassumerolepolicygenerator.py."
        )
        quit()
    except ParamValidationError:
        print(
            "You did not provide a role name as an option. Try again with a valid role."
        )
        quit()
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            print(
                f"IAM user account is missing the iam:GetRole permission. Review the example policy in the repo and modify appropriately. Quitting..."
            )
            quit()


def revert_policy(iam_client, args):
    print("\nReverting UpdateAssumeRolePolicy policy back to default deny all...")
    revert_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": ["sts:AssumeRole"]}
        ],
    }
    policy_document_str = json.dumps(revert_policy_document)
    try:
        iam_client.update_assume_role_policy(
            PolicyDocument=policy_document_str, RoleName=args.rolename
        )
        print("Policy reverted successfully.")
    except Exception:
        print("Failed to revert policy. Update it manually in AWS console.")


def user_enum(args):
    try:
        found_users = 0
        timeout = int(args.timeout) if args.timeout else 0
        print(
            f"Finding valid IAM usernames in {args.account} utilizing the IAM\nUpdateAssumeRolePolicy method. Please be patient...\n"
        )
        session = boto3.Session(
            aws_access_key_id=args.accesskey, aws_secret_access_key=args.secretkey
        )
        iam_client = session.client("iam")
        sts_client = session.client("sts")
        try:
            sts_client.get_caller_identity()
        except ClientError as e:
            if e.response["Error"]["Code"] == "SignatureDoesNotMatch":
                print(
                    "\nInvalid Signature. Access key and secret key may be incorrect.\nQuitting..."
                )
                quit()
            else:
                print(f"\nSome issue occurred: {e}.\nQuitting...")
        permissions_check(iam_client, args)

        def process_username(username):
            """Process a single username."""
            nonlocal found_users
            arn_val = f"arn:aws:iam::{args.account}:user/{username}"
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": arn_val},
                        "Action": ["sts:AssumeRole"],
                    }
                ],
            }
            policy_document_str = json.dumps(policy_document)
            try:
                if timeout:
                    time.sleep(timeout)
                enum_user = iam_client.update_assume_role_policy(
                    PolicyDocument=policy_document_str,
                    RoleName=args.rolename,
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
        revert_policy(iam_client, args)
        print(f"\n{found_users} valid IAM usernames found. Quitting...")
    except KeyboardInterrupt:
        print("\nOperation interrupted.")
        revert_policy(iam_client, args)
