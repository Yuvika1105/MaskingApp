import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
POLICIES_DIR = DATA_DIR / "masking_policies"
TEMP_DIR = BASE_DIR / "temp"

# Ensure directories exist
for directory in [DATA_DIR, POLICIES_DIR, TEMP_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Default Policy Paths
DEFAULT_POLICY_PATH = POLICIES_DIR / "default_policy.yaml"
MG_POLICY_PATH = POLICIES_DIR / "mg_policy.yaml"
