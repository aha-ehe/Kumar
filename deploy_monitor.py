import paramiko
import os
import sys

def deploy_file(local_path, remote_path):
    hostname = "36.88.105.236"
    port = 22
    username = "unira5"
    key_path = os.path.expanduser("~/.ssh/id_rsa")

    if not os.path.exists(local_path):
        print(f"Error: Local file {local_path} not found.")
        return False

    print(f"Deploying {local_path} to {username}@{hostname}:{remote_path}...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=port, username=username, key_filename=key_path)

        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()

        # Ensure execution permissions
        ssh.exec_command(f"chmod +x {remote_path}")

        ssh.close()
        print("Deployment successful.")
        return True
    except Exception as e:
        print(f"Deployment failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 deploy_monitor.py <local_file> <remote_path>")
        sys.exit(1)

    deploy_file(sys.argv[1], sys.argv[2])
