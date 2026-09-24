from dataclasses import dataclass


@dataclass
class Signal:
    id: str
    type: str
    score: int
    source: str
