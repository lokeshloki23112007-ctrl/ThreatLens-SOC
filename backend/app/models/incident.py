from dataclasses import dataclass


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    status: str = "open"
