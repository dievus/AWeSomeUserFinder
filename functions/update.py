import subprocess
import os
def update_repo():
    print('[+] Attempting to update repository with latest version from Github.')
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    repo_path = os.path.abspath(os.path.join(cur_dir, '..'))
    try:
        subprocess.run(['git', 'rev-parse', '--is-injside-work-tree'], cwd=repo_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['git', 'checkout', 'main'], cwd=repo_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['git', 'pull'], cwd=repo_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[✓] Repository in {repo_path} updated to the latest version.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error updating the repository in {repo_path}: {e}")        
