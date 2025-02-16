import argparse
import textwrap
import sys
from functions.assumerole import user_enum
from functions.banner import *
from functions.s3 import bucket_enum
from functions.sns import sns_handler
from functions.spray import spray


def options():
    opt_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """Example: python3 AWeSomeConsoleUserFinder.py -a 1234567890 -f -ak <accesskey> -sk <secretkey> -rf users.txt\n         python3 AWeSomeConsoleUserFinder.py -a 1234567890 -s -p Password -rf users.txt
"""
        ),
    )
    requiredArgs = opt_parser.add_argument_group(
        'Required Enumeration Arguments')
    snsArgs = opt_parser.add_argument_group(
        'SNS Enumeration Method Required Arguments')
    iamArgs = opt_parser.add_argument_group(
        'IAM UpdateAssumeRolePolicy Required Arguments')
    s3Args = opt_parser.add_argument_group(
        'S3 Enumeration Method Required Arguments')
    sprayArgs = opt_parser.add_argument_group(
        'Password Spraying Required Arguments')
    optionalArgs = opt_parser.add_argument_group('Optional Arguments')
    optionalArgs.add_argument(
        "-t", "--timeout", help="Set pause time between password spraying attempts. Default - 2 seconds")
    optionalArgs.add_argument(
        "-v", "--verbose", help="Prints output verbosely", action="store_true"
    )
    requiredArgs.add_argument(
        "-a", "--account", help="AWS account to check for IAM users")
    requiredArgs.add_argument(
        "-rf", "--read", help="Reads usernames from a file to test")
    requiredArgs.add_argument("-ak", "--accesskey",
                              help="Access key for enumerating users")
    requiredArgs.add_argument("-sk", "--secretkey",
                              help="Secret key for enumerating users")
    snsArgs.add_argument(
        "-sns", "--snsenum", help="Uses SNS policy modification for enumeration", action="store_true"
    )
    snsArgs.add_argument(
        "-ta", "--topicarn", help="Topic Arn to modify"
    )
    snsArgs.add_argument(
        "-r", "--region", help="Specify a region to use with SNS enumeration"
    )
    iamArgs.add_argument(
        "-i", "--iam", help="Uses IAM policy modification for enumeration", action="store_true")
    iamArgs.add_argument(
        "-rn", "--rolename", help="Role name to add to the assume policy document")
    s3Args.add_argument(
        "-s3", "--s3enum", help="Uses s3 bucket policy modification for enumeration", action="store_true")
    s3Args.add_argument(
        "-b", "--bucket", help="Bucket name to use for s3 policy")
    # opt_parser.add_argument(
    #     "-sns", "--snsenum", help="Uses SNS policy modification for enumeration", action="store_true"
    # )
    # opt_parser.add_argument(
    #     "-ta", "--topicarn", help="Topic Arn to modify"
    # )
    # opt_parser.add_argument(
    #     "-r", "--region", help="Specify a region to use with SNS enumeration"
    # )
    sprayArgs.add_argument(
        "-s", "--spray", help="Password spray a list of account names", action="store_true")
    sprayArgs.add_argument("-p", "--password", help="Password to spray")
    # opt_parser.add_argument(
    #     "-f", "--find", help="Find valid AWS IAM account names", action="store_true")
    # opt_parser.add_argument(
    #     "-t", "--timeout", help="Set pause time between password spraying attempts. Default - 2 seconds")
    # opt_parser.add_argument(
    #     "-v", "--verbose", help="Prints output verbosely", action="store_true"
    # )
    global args
    args = opt_parser.parse_args()
    if len(sys.argv) == 1:
        opt_parser.print_help()
        opt_parser.exit()


if __name__ == "__main__":
    try:
        banner()
        options()
        if args.iam:
            if args.iam and args.rolename:
                user_enum(args)
            else:
                print(
                    'Parameters are missing from the command. Review the help menu and try again. Quitting...')
                quit()
        elif args.s3enum:
            if args.s3enum and args.bucket:
                bucket_enum(args)
            else:
                print(
                    'Parameters are missing from the command. Review the help menu and try again. Quitting...')
                quit()
        elif args.snsenum:
            if args.snsenum and args.topicarn and args.region:
                sns_handler(args)
            else:
                print(
                    'Parameters are missing from the command. Review the help menu and try again. Quitting...')
                quit()
        elif args.spray:
            if args.spray and args.password and args.account:
                spray(args)
            else:
                print(
                    'Parameters are missing from the command. Review the help menu and try again. Quitting...')
                quit()
    except KeyboardInterrupt:
        print('You either fat fingered this, or something else. Otherwise, quitting!')
        quit()
