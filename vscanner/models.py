from dataclasses import asdict, dataclass
from typing import Dict


@dataclass
class Finding:
    severity: str
    title: str
    details: str
    recommendation: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)
