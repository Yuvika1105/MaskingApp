import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class MaskingPolicy:
    column_rules: Dict[str, str] = field(default_factory=dict)
    entity_rules: List[str] = field(default_factory=list)
    replacement_map: Dict[str, str] = field(default_factory=dict)
    domain_config: Dict[str, any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, file_path: str) -> "MaskingPolicy":
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Masking policy file not found at: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(
            column_rules=data.get("column_rules", {}),
            entity_rules=data.get("entity_rules", []),
            replacement_map=data.get("replacement_map", {}),
            domain_config=data.get("domain_config", {})
        )
