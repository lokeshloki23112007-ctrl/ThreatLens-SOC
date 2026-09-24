from dataclasses import dataclass


@dataclass
class SOCQueue:
    queue_id: str
    priority: str
    assigned_team: str
    status: str = "queued"
