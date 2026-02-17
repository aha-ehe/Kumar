import paramiko
import time
import os
import sys

def setup_firewall():
    hostname = "36.88.105.236"
    port = 22
    username = "unira5"
    key_path = os.path.expanduser("~/.ssh/id_rsa")
    password = os.environ.get("SSH_PASS")

    if not password:
        print("Error: SSH_PASS environment variable is not set. Cannot authenticate as root.")
        sys.exit(1)

    print(f"Connecting to {username}@{hostname}...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(hostname, port=port, username=username, key_filename=key_path)
        shell = client.invoke_shell()

        # Helper to read output
        def read_until(pattern, timeout=5):
            end_time = time.time() + timeout
            output = ""
            while time.time() < end_time:
                if shell.recv_ready():
                    chunk = shell.recv(1024).decode('utf-8')
                    output += chunk
                    if pattern in output:
                        return output
                time.sleep(0.1)
            return output

        # Switch to root
        print("Attempting to switch to root...")
        shell.send("su -\n")
        time.sleep(1)
        resp = read_until("Password:")
        if "Password:" in resp:
             print(f"Password prompt received.")
        else:
             print("Warning: Password prompt not detected, sending password anyway...")

        shell.send(password + "\n")
        time.sleep(1)
        resp = read_until("#") # Wait for root prompt

        if "#" in resp:
            print("Root access granted.")
        else:
            print("Failed to get root prompt. Commands may fail.")

        # Commands to execute
        commands = [
            "iptables -I INPUT -p tcp --dport 7890 -j ACCEPT",
            "ufw allow 7890/tcp",
            # "firewall-cmd --zone=public --add-port=7890/tcp --permanent", # Known to fail on Debian
            # "firewall-cmd --reload",
            "netstat -tulnp | grep 7890"
        ]

        for cmd in commands:
            print(f"Executing: {cmd}")
            shell.send(cmd + "\n")
            time.sleep(1)
            resp = read_until("#")
            print(resp)

        client.close()
        print("Firewall configuration attempt complete.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    setup_firewall()
