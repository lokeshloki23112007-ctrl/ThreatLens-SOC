from dataclasses import dataclass


@dataclass
class Recipient:
    email: str
    risk_score: int = 0
    status: str = "pending"
