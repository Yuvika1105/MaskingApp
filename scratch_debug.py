import pandas as pd
from config import DEFAULT_POLICY_PATH
from app.data_masking.masking_policy import MaskingPolicy
from app.data_masking.masking_engine import MaskingEngine

policy = MaskingPolicy.from_yaml(str(DEFAULT_POLICY_PATH))
engine = MaskingEngine(policy)

df = pd.read_excel(r"C:\Users\interview\Downloads\Synthetic_Confidential_Customer_Data_With_Models.xlsx")

# Check selected entities (PERSON, EMAIL_ADDRESS)
selected_entities = ["PERSON", "EMAIL_ADDRESS"]
custom_redact_list = ["Xama"]

def apply_custom_redactions(val):
    if pd.isna(val):
        return val
    val_str = str(val).strip()
    masked_val = val_str
    if custom_redact_list:
        import re
        for term in custom_redact_list:
            tag_pattern = re.compile(rf"<[A-Z_]*{re.escape(term.upper())}[A-Z_]*>", re.IGNORECASE)
            masked_val = tag_pattern.sub("#", masked_val)
            substring_pattern = re.compile(re.escape(term), re.IGNORECASE)
            masked_val = substring_pattern.sub("#", masked_val)
    return masked_val

def mask_cell(val):
    if pd.isna(val):
        return val
    val_str = str(val).strip()
    val_redacted = apply_custom_redactions(val_str)
    res = engine.mask_text(val_redacted)
    masked_val = res.masked_text
    masked_val = apply_custom_redactions(masked_val)
    return masked_val

# Run on first 5 rows of Full_Name
for i in range(5):
    val = df.loc[i, "Full_Name"]
    res = mask_cell(val)
    print(f"Row {i}: {val} -> {res}")
