from dataclasses import dataclass


@dataclass
class IEVIScore:
    """
    Represents the calculated risk index based on the paper's formula.
    Ref: [cite: 96, 172]
    """

    damage_potential: int  # D
    reproducibility: int  # R
    exploitability: int  # E
    affected_users: int  # A
    discoverability: int  # D
    total_score: float  # The calculated IEVI
    risk_level: str  # 'Critical', 'Tolerable', etc.
