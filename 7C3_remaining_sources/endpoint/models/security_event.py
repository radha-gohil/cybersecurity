from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4


@dataclass
class SecurityEvent:
    event_type: str
    source: str

    device_id: str = "local-device"
    severity: str = "INFO"

    process: Optional[Dict[str, Any]] = None
    file: Optional[Dict[str, Any]] = None
    network: Optional[Dict[str, Any]] = None
    registry: Optional[Dict[str, Any]] = None

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    event_id: str = field(
        default_factory=lambda: str(uuid4())
    )

    timestamp: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "process": self.process,
            "file": self.file,
            "network": self.network,
            "registry": self.registry,
            "metadata": self.metadata,
        }