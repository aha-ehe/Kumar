import paramiko
import time
import os
import sys

def cleanup_project():
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

        # 1. Kill Processes
        print("Killing monitor processes...")
        client.exec_command("pkill -f server_monitor.py")
        client.exec_command("pkill -f monitor_web.py")
        time.sleep(1)

        # 2. Delete Files
        print("Deleting project files...")
        files_to_remove = [
            "server_monitor.py",
            "monitor_web.py",
            "monitor.db",
            "scan.log",
            "web.log",
            "monitor_dashboard.html"
        ]
        for f in files_to_remove:
            client.exec_command(f"rm -f {f}")
            print(f"Removed {f}")

        # 3. Close Firewall
        shell = client.invoke_shell()

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

        print("Attempting to switch to root for firewall cleanup...")
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
            # Firewall Commands
            commands = [
                "iptables -D INPUT -p tcp --dport 7890 -j ACCEPT",
                "ufw delete allow 7890/tcp",
                "netstat -tulnp | grep 7890" # Should be empty
            ]

            for cmd in commands:
                print(f"Executing: {cmd}")
                shell.send(cmd + "\n")
                time.sleep(1)
                resp = read_until("#")
                print(resp)
        else:
            print("Failed to get root prompt. Firewall rules may persist.")

        client.close()
        print("Cleanup complete.")

    except Exception as e:
        print(f"Error during cleanup: {e}")

if __name__ == "__main__":
    cleanup_project()
