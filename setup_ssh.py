import paramiko
import os
import sys

def setup_ssh_key():
    hostname = "36.88.105.236"
    port = 22
    username = "unira5"
    password = os.environ.get("SSH_PASS")

    if not password:
        print("Error: SSH_PASS environment variable not set.")
        sys.exit(1)

    key_path = os.path.expanduser("~/.ssh/id_rsa.pub")
    if not os.path.exists(key_path):
        print(f"Error: Public key file not found at {key_path}")
        sys.exit(1)

    with open(key_path, "r") as f:
        public_key = f.read().strip()

    print(f"Connecting to {username}@{hostname}:{port}...")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port=port, username=username, password=password)

        print("Connected successfully.")

        # Ensure .ssh directory exists and has correct permissions
        stdin, stdout, stderr = client.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
        if stdout.channel.recv_exit_status() != 0:
             print(f"Error creating ~/.ssh: {stderr.read().decode()}")
             sys.exit(1)

        # Append public key to authorized_keys if not present
        check_cmd = f"grep -F '{public_key}' ~/.ssh/authorized_keys"
        stdin, stdout, stderr = client.exec_command(check_cmd)

        if stdout.channel.recv_exit_status() != 0:
            print("Adding public key to authorized_keys...")
            append_cmd = f"echo '{public_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
            stdin, stdout, stderr = client.exec_command(append_cmd)
            if stdout.channel.recv_exit_status() != 0:
                print(f"Error appending key: {stderr.read().decode()}")
                sys.exit(1)
            print("Public key added successfully.")
        else:
            print("Public key already exists in authorized_keys.")

        client.close()
        print("SSH setup complete.")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    setup_ssh_key()
