from dataclasses import dataclass


@dataclass
class Campaign:
    id: str
    name: str
    status: str = "active"
