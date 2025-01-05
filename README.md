# AWeSomeUserFinder
AWS IAM Username Enumerator and Password Spraying Tool in Python3

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

<p align="left">
  <img src="https://github.com/dievus/AWeSomeUserFinder/blob/main/images/image2.png"/>
</p>

## Setup

### Update Assume Role Policy Method

<p align="left">
  <img src="https://github.com/dievus/AWeSomeUserFinder/blob/main/images/image5.png" />
</p>

In order to use the tool with the UpdateAssumeRolePolicy method, the IAM user account utilized must have the following permissions attached:

- "iam:GetRole"
- "iam:CreatePolicy"
- "iam:UpdateAssumeRolePolicy"
- "iam:CreateRole"
- "iam:AttachRolePolicy"

An example policy is included in the files named "example_assume_role_policy.json" in the example_policies directory.

Additionally, an AWS access key and AWS secret key are required. See this link for information on obtaining them - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

Finally, a role is needed with an attached policy granting "UpdateAssumeRolePolicy," which also has a TrustedEntity Deny all rule for AssumeRole permissions. This can be somewhat convoluted, so there is an additional script included with the tool called, "updateassumerolepolicygenerator.py." Using an access key and secret key, along with the required permissions noted above, the correct policy and role will be generated automatically and be usable until it is manually removed. Both the new policy and role will be named "user_enumeration_policy."

Run the tool with `python3 updateassumerolepolicygenerator.py`, and enter the keys when requested.

<p align="left">
  <img src="https://github.com/dievus/AWeSomeUserFinder/blob/main/images/image3.png" />
</p>

### S3 Bucket Method

<p align="left">
  <img src="https://github.com/dievus/AWeSomeUserFinder/blob/main/images/image4.png" />
</p>

In order to use the tool with the S3 bucket method, you will need to create a new, general-purpose S3 bucket. Set "Block All Public Access" to the bucket. Next, a new policy needs to be added to the AWS account and attached to the IAM user of choice. The policy must have the following permissions attached to the user:

- "s3:PutBucketPolicy"
- "s3:GetBucketPolicy"
- ARN referenced to the S3 bucket created earlier.

An example policy is included in the files named "example_s3_policy" in the example_policies directory. 

Additionally, an AWS access key and AWS secret key are required. See this link for information on obtaining them - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

## Username Enumeration
AWeSomeUserFinder's username enumeration function utilizes Boto3, and exploits valid AWS functionality in IAM role policies to enumerate valid IAM usernames in other AWS accounts. AWS allows administrators to create allow and deny rules for external resources, which is abusable by modifying "UpdateAssumeRolePolicy" to set a deny rule for the external ARN. If the username is valid, the policy is modified, and if it is invalid, AWS responds that the principal cannot be found. In order to exploit this feature, the attacker needs:

- Role policy that allows an IAM user account under the attacker's control to assume the role in their own AWS account
- Account ID for the victim/target
- Controlled account's Access and Secret Keys

Required flags for enumerating accounts:

- `-f, --find` - Find valid accounts with the UpdateAssumeRolePolicy method
- `-s3, --s3enum` - Find valid accounts with the S3 method
- `-ak, --accesskey` - Access key for controlled account
- `-sk, --secretkey` - Secret key for controlled account
- `-rn, --rolename` - Role name controlled by attacker for UpdateAssumeRolePolicy method
- `-b, --bucket` - Name of the bucket controlled by attacker for S3 method
- `-r, --read` - List of possible user names to enumerate
- `-a, --account` - Account ID for victim account

To enumerate accounts, run the following:

`python3 AWeSomeUserFinder.py -f -ak <accesskey> -sk <secretkey> -a <account_id> -r <username_list> -rn <role_name>`

## Password Spraying
AWeSomeUserFinder's password spraying function attempts to authenticate through the AWS IAM console logon form, and utilizes Python's requests library. By parsing responses, it is possible to identify valid account credentials. In order to spray the console, the attacker needs:

- Account ID for the victim/target
- List of possible or confirmed IAM account names

Required flags for password spraying:

- `-s, --spray` - Required flag for password spraying
- `-a, --account` - Account ID for victim account
- `-r, --read` - List of usernames to password spray
- `-t, --timeout` - Optional flag to set a pause between each attempt (default - 2 seconds)

To password spray, run the following:

`python3 AWeSomeUserFinder.py -s -a <account_id> -r <username_list>`

The default time between spray attempts is set to two seconds to counter AWS from actively defending against the attack. Anything faster than two seconds will eventually result in error messaging.

## To Do

- [X] Print to console output when account requires a password change on next login
- [X] Build script to automate generation of required role and policy
- [ ] Explore additional ways beyond UpdateAssumeRolePolicy to enumerate users

## Disclaimer

Always ensure that you have proper permissions to utilize any offensive attack tool, including this one. Refer to the terms and services of AWS for details on conducting penetration tests against endpoints and services hosted by AWS.
