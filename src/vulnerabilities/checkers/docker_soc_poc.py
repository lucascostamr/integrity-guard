from os import path, remove
from subprocess import PIPE, run
from uuid import uuid4

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
        host_path = f"/tmp/{test_filename}"

        # Command replicates the attack flow in Figure 2 [cite: 111-114]
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            "/etc:/mnt/host_tmp",
            "alpine",
            "sh",
            "-c",
            f"echo 'PoC' > /mnt/host_tmp/{test_filename}",
        ]

        try:
            run(cmd, stdout=PIPE, stderr=PIPE, timeout=10)

            if path.exists(host_path):
                remove(host_path) if self.cleanup else None

                return ScanResult(
                    check_id=self.ID,
                    check_name=self.NAME,
                    is_vulnerable=True,
                    severity=Severity.CRITICAL,
                    description="Verifies if a container can modify host files (Data Tampering).",
                    evidence="Successfully wrote file to host /tmp via container volume.",
                )
        except FileNotFoundError:
            return ScanResult(
                self.ID, self.NAME, False, Severity.INFO, "Docker CLI not found", "None"
            )
        except Exception:
            pass

        return ScanResult(
            check_id=self.ID,
            check_name=self.NAME,
            is_vulnerable=False,
            severity=Severity.LOW,
            description="Verifies if a container can modify host files.",
            evidence="Write attempt failed or container runtime unreachable.",
        )
