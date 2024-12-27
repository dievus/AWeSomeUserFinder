# AWeSomeUserFinder
AWS IAM Username Enumerator and Password Spraying Tool in Python3

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

<p align="center">
  <img src="https://github.com/dievus/AWeSomeUserFinder/blob/main/images/image1.png" />
</p>

<p align="center">
  <img src="https://github.com/dievus/AWeSomeUserFinder/blob/main/images/image2.png" />
</p>

## Username Enumeration
AWeSomeUserFinder's username enumeration function utilizes Boto3, and exploits valid AWS functionality in IAM role policies to enumerate valid IAM usernames in other AWS accounts. AWS allows administrators to create allow and deny rules for external resources, which is abusable by modifying "UpdateAssumeRolePolicy" to set a deny rule for the external ARN. If the username is valid, the policy is modified, and if it is invalid, AWS responds that the principal cannot be found. In order to exploit this feature, the attacker needs:

- Role policy that allows an IAM user account under the attacker's control to assume the role in their own AWS account
- Account ID for the victim/target
- Controlled account's Access and Secret Keys

Required flags for enumerating accounts:

- `-f, --find` - Find valid accounts
- `-ak, --accesskey` - Access key for controlled account
- `-sk, --secretkey` - Secret key for controlled account
- `-rn, --rolename` - Role name controlled by attacker
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

- [x] Logic to identify MFA when password spraying
- [ ] Explore additional ways beyond UpdateAssumeRolePolicy to enumerate users

## Disclaimer

Always ensure that you have proper permissions to utilize any offensive attack tool, including this one. Refer to the terms and services of AWS for details on conducting penetration tests against endpoints and services hosted by AWS.
