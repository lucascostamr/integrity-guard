from grp import getgrall
from os import getenv

from domain.scan_result import ScanResult
from domain.severity import Severity
from interfaces.vulnerability_check import VulnerabilityCheck


class DockerGroupCheck(VulnerabilityCheck):
    """
    Implements the Diagnosis Module (Section 4.1).
    Checks if current user is in 'docker' group.
    """

    ID = "DX-001"
    NAME = "User Docker Group Membership"
    
    def execute(self) -> ScanResult:
        user = getenv("USER")
        is_member = False
        evidence = "User is not in docker group."

        try:
            # Logic to check group membership
            groups = [g.gr_name for g in getgrall() if user in g.gr_mem]
            if "docker" in groups:
                is_member = True
                evidence = f"User '{user}' found in 'docker' group."
        except Exception as e:
            evidence = f"Error checking groups: {str(e)}"

        return ScanResult(
            check_id=self.ID,
            check_name=self.NAME,
            is_vulnerable=is_member,
            severity=Severity.CRITICAL if is_member else Severity.LOW,
            description="Checks if the user has root-equivalent access via docker group.",
            evidence=evidence,
        )
