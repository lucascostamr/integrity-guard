from typing import List

from domain.ievi_score import IEVIScore
from domain.scan_result import ScanResult


class IEVICalculator:
    """
    Service responsible for calculating the Integrity Violation Exposure Index (IEVI).
    Logic derived from the DREAD model extension proposed in the article.
    """

    def calculate(self, results: List[ScanResult]) -> IEVIScore:
        # Default baseline (Safe/Mitigated Scenario)
        # Based on 'Scenario Mitigated' values from Table 2 [cite: 170]
        d, r, e, a, di = 3, 4, 4, 3, 4
        risk_label = "TOLERABLE"

        # Analyze findings to adjust DREAD values
        # If Critical Vulnerabilities are found (specifically Docker Socket issues)
        root_access_risk = any(
            res.is_vulnerable and res.check_id in ["DX-001", "DX-002"]
            for res in results
        )

        if root_access_risk:
            # Replicates 'Scenario Vulnerable' values from Table 2 [cite: 170]
            # D=10 (System Corruption/Privilege) [cite: 97]
            # R=10 (Trivial reproducibility) [cite: 100]
            # E=10 (Trivial exploitability via docker client) [cite: 101]
            # A=10 (All users on host potentially affected) [cite: 102]
            # Di=10 (Easy discovery via 'groups' command) [cite: 103]
            d, r, e, a, di = 10, 10, 10, 10, 10
            risk_label = "CRITICAL"

        # Calculate IEVI Formula: (Sum / 5) * 10 [cite: 96]
        raw_average = (d + r + e + a + di) / 5
        ievi_total = raw_average * 10

        return IEVIScore(
            damage_potential=d,
            reproducibility=r,
            exploitability=e,
            affected_users=a,
            discoverability=di,
            total_score=ievi_total,
            risk_level=risk_label,
        )
