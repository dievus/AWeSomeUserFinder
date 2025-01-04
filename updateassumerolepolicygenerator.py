import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

def banner():
    print('\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+') 
    print('|U|p|d|a|t|e|A|s|s|u|m|e|R|o|l|e|P|o|l|i|c|y|') 
    print('+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+') 
    print('|             G|e|n|e|r|a|t|o|r             |')                           
    print('+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-++-+-+-+')                           

def policy_gen(accesskey, secretkey):
    policy_name = 'user_enumeration_policy'
    session = boto3.Session(
        aws_access_key_id=accesskey,
        aws_secret_access_key=secretkey
    )
    iam_client = session.client("iam")
    try:
        created_policy_document = '{"Version": "2012-10-17","Statement": [{"Sid": "Enum","Effect": "Allow","Action": ["iam:UpdateAssumeRolePolicy"],"Resource": "*"}]}'
        create_policy = iam_client.create_policy(PolicyName=policy_name, PolicyDocument=created_policy_document)
        if create_policy:
            policy_arn = create_policy["Policy"]["Arn"]
            policy_document = '{"Version": "2012-10-17","Statement": [{"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": ["sts:AssumeRole"]}]}'
            iam_client.create_role(RoleName=policy_name, AssumeRolePolicyDocument=policy_document)
            iam_client.attach_role_policy(RoleName=policy_name, PolicyArn=policy_arn)
            print(f"New policy and role named {policy_name} created for use now and in the future.")
        else:
            print('Some error occurred. Try again, or run manually.')
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f'\nThe necessary policy is already generated with the name {policy_name}. Quitting.')
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            print(f'\nThere is a permissions error with the IAM user used. Check the Github for details and try again. Quitting...')
    except EndpointConnectionError as e:
        print(f'An error occurred connecting to the appropriate AWS endpoint. Issue: {e}.')
if __name__ == "__main__":
    try:
        banner()
        print('\nThis tool will generate the appropriate policy and role for enumerating valid IAM users in an external account.\n')
        accesskey = input("Enter a valid user access key value: ")
        secretkey = input("Enter a valid user secret key value: ")
        policy_gen(accesskey, secretkey)
    except KeyboardInterrupt:
        print('\nYou either fatfingered this, or something else. Either way, quitting!')
    except Exception as e:
        print(f'\nSome other error occurred. Feel free to open a new issue on Github. Please provide the following: {e}.')
