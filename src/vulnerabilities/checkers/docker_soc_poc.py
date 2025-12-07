from os import path
from uuid import uuid4

from docker import from_env
from docker.errors import DockerException

from domain.scan_result import ScanResult
from domain.severity import Severity
from interfaces.vulnerability_check import VulnerabilityCheck


class DockerSockPoC(VulnerabilityCheck):
    """
    Implements the Safe PoC (Section 3.4).
    Simulates writing to host filesystem to prove Data Tampering risk.
    """

    ID = "DX-002"
    NAME = "Docker Socket Host Write PoC"

    def __init__(self, cleanup: bool = True):
        self.cleanup = cleanup

    def execute(self) -> ScanResult:
        test_filename = f"integrity_guard_{uuid4().hex}.test"
        host_path = "/etc"
        file_path = path.join(host_path, test_filename)

        try:
            client = from_env()

            client.containers.run(
                image="alpine",
                command=f"sh -c 'echo PoC > /mnt/host_tmp/{test_filename}'",
                remove=True,
                volumes={
                    host_path : {'bind': '/mnt/host_tmp', 'mode': 'rw'}
                }
            )

            if not path.exists(file_path):
                return ScanResult(
                    check_id=self.ID,
                    check_name=self.NAME,
                    is_vulnerable=False,
                    severity=Severity.LOW,
                    description="Verifies if a container can modify host files.",
                    evidence="Write attempt failed or container runtime unreachable.",
                )

            if self.cleanup:
                client.containers.run(
                    image="alpine",
                    command=f"sh -c 'rm /mnt/host_tmp/{test_filename}'",
                    remove=True,
                    volumes={
                        host_path : {'bind': '/mnt/host_tmp', 'mode': 'rw'}
                    }
                )

            return ScanResult(
                check_id=self.ID,
                check_name=self.NAME,
                is_vulnerable=True,
                severity=Severity.CRITICAL,
                description="Verifies if a container can modify host files (Data Tampering).",
                evidence=f"Successfully wrote file to host {host_path} via container volume.",
            )

        except DockerException as e:
            return ScanResult(
                self.ID, self.NAME, False, Severity.INFO, "Docker daemon unreachable", str(e)
            )
        except Exception:
            return ScanResult(
                check_id=self.ID,
                check_name=self.NAME,
                is_vulnerable=False,
                severity=Severity.LOW,
                description="Verifies if a container can modify host files.",
                evidence="Write attempt failed or container runtime unreachable.",
            )
