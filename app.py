# app.py
import re
import io
import time
import pandas as pd
import streamlit as st

# Import the existing generalized backend modules
from config import POLICIES_DIR, DEFAULT_POLICY_PATH
from app.data_masking.masking_policy import MaskingPolicy
from app.data_masking.masking_engine import MaskingEngine

# Set premium, professional page configuration
st.set_page_config(
    page_title="SafeGuard — Standalone Masking Portal",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Premium interface styling (Outfit + Plus Jakarta typography)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Plus+Jakarta+Sans:wght@300;400;500;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    .portal-title {
        font-family: 'Outfit', sans-serif;
        font-size: 2.8rem !important;
        font-weight: 800;
        background: linear-gradient(135deg, #0ea5e9, #6366f1, #a855f7);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
        text-align: center;
    }
    
    .portal-subtitle {
        font-size: 1.15rem !important;
        color: #6b7280;
        text-align: center;
        margin-bottom: 2.5rem;
    }
</style>
""", unsafe_allow_html=True)

# Main Title & Subtitle
st.markdown('<div class="portal-title">Data Masking Portal</div>', unsafe_allow_html=True)

st.divider()

# File Upload Section
st.subheader("1. Upload Document")
uploaded_file = st.file_uploader(
    "Select raw dataset to sanitize", 
    type=["csv", "xlsx", "xls"],
    help="Supports standard comma-separated text files (.csv) and Microsoft Excel spreadsheets (.xlsx, .xls)"
)

if uploaded_file is not None:
    file_name = uploaded_file.name
    file_bytes = uploaded_file.getvalue()
    
    # Try/except block to handle file reading gracefully
    try:
        if file_name.endswith('.csv'):
            df = pd.read_csv(io.BytesIO(file_bytes))
        else:
            df = pd.read_excel(io.BytesIO(file_bytes))
            
        st.success(f"Successfully loaded `{file_name}` ({len(df)} rows, {len(df.columns)} columns)")
        
        # Display raw data preview
        with st.expander("View Raw Data Preview (First 5 Rows)", expanded=True):
            st.dataframe(df.head(5), use_container_width=True)
            
        st.divider()
        
        # -------------------------------------------------------------
        # AUTOMATIC SCHEMA DETECTION & COMPONENT MAPPING
        # -------------------------------------------------------------
        # Scan all available policy files to load aggregate column mappings
        all_column_rules = {}
        all_replacement_maps = {}
        domain_configs = {}
        
        for pf in POLICIES_DIR.glob("*.yaml"):
            try:
                p = MaskingPolicy.from_yaml(str(pf))
                all_column_rules.update(p.column_rules)
                all_replacement_maps.update(p.replacement_map)
                if p.domain_config:
                    domain_configs.update(p.domain_config)
            except Exception:
                pass
                
        # Discover which specific entities are related to the columns of the uploaded file
        detected_entities = []
        for col in df.columns:
            entity = None
            # Perform a case-insensitive check against known column rules
            for rule_col, rule_ent in all_column_rules.items():
                if col.strip().lower() == rule_col.strip().lower():
                    entity = rule_ent
                    break
            if entity and entity not in detected_entities:
                detected_entities.append(entity)
                
        # Default fallback to standard PII entities if no columns match any pre-configured policy rules
        if not detected_entities:
            detected_entities = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "ORGANIZATION"]
            
        # -------------------------------------------------------------
        # Dynamic Configuration Section
        # -------------------------------------------------------------
        st.subheader("2. Configuration & Sensitivity Rules")
        st.write("Configure column-level overrides, smart PII scanner boundaries, and custom word targets.")
        
        cfg_col1, cfg_col2, cfg_col3 = st.columns(3)
        
        with cfg_col1:
            with st.container(border=True):
                st.write("### A: Full Column Redaction")
                st.caption("Select columns to fully redact with a static placeholder (`<REDACTED>`).")
                
                fully_masked_cols = st.multiselect(
                    "Select columns to fully redact:",
                    options=df.columns.tolist(),
                    help="Every cell under these columns will be permanently replaced with '<REDACTED>'."
                )
            
        with cfg_col2:
            with st.container(border=True):
                st.write("### B: Smart Entity Recognition")
                st.caption("Select PII or custom entities to scan for and redact in remaining columns.")
                
                # Dynamic file-specific scanners!
                entity_options = detected_entities
                
                selected_entities = st.multiselect(
                    "Select entities to detect and redact:",
                    options=entity_options,
                    default=entity_options,  # Automatically check all matching scanners by default
                    help="The engine will scan cell strings in the remaining columns and mask matching instances."
                )
            
        with cfg_col3:
            with st.container(border=True):
                st.write("### C: Custom Term Redaction")
                st.caption("Provide a comma-separated list of bespoke phrases or codes (e.g. `MG, Tata, Tesla`) to target.")
                
                custom_redact_terms = st.text_input(
                    "Enter custom terms to mask (comma-separated):",
                    placeholder="e.g., MG, Tata, Tesla",
                    help="The engine will perform case-insensitive redactions, replacing occurrences and related entity tags with '#'."
                )
                
                # Parse comma-separated custom terms
                custom_redact_list = [t.strip() for t in custom_redact_terms.split(",") if t.strip()] if custom_redact_terms else []
                if custom_redact_list:
                    st.info(f"Targeting {len(custom_redact_list)} custom phrases for direct redaction.")
            
        st.divider()
        
        # Execution & Processing Section
        st.subheader("3. Execution & Sanitization Engine")
        
        if st.button("Apply Security Policies & Run Masking", type="primary", use_container_width=True):
            with st.spinner("Executing dynamic data sanitization... Please wait."):
                start_time = time.time()
                
                # Make a copy of the dataframe to prevent side-effects
                sanitized_df = df.copy()
                
                # Build a dynamic policy specifically tailored to the uploaded schema
                base_policy = MaskingPolicy(
                    column_rules={c: all_column_rules[c] for c in df.columns if c in all_column_rules},
                    entity_rules=selected_entities,
                    replacement_map=all_replacement_maps,
                    domain_config=domain_configs
                )
                
                # Initialize the masking engine using our updated policy
                engine = MaskingEngine(base_policy)
                
                # STEP A: Apply full column-level overrides (Control A)
                for col in fully_masked_cols:
                    sanitized_df[col] = "<REDACTED>"
                    
                # STEP B: Apply smart entity-level scanner (Control B) and Custom Redactions (Control C)
                remaining_cols = [c for c in df.columns if c not in fully_masked_cols]
                
                # Cell-level dynamic masking processor
                def mask_cell(val):
                    if pd.isna(val):
                        return val
                    
                    val_str = str(val).strip()
                    if not val_str:
                        return ""
                    
                    # 1. Apply Presidio Smart Entity Masking
                    res = engine.mask_text(val_str)
                    masked_val = res.masked_text
                    
                    # 2. Apply Custom Word / Phrase Redaction (Control C)
                    if custom_redact_list:
                        for term in custom_redact_list:
                            # A. Sanitize entity tags containing the custom brand term (e.g. <MG_BRAND> -> #)
                            # to avoid disclosing the brand name inside the redact placeholder
                            tag_pattern = re.compile(rf"<[A-Z_]*{re.escape(term.upper())}[A-Z_]*>", re.IGNORECASE)
                            masked_val = tag_pattern.sub("#", masked_val)
                            
                            # B. Direct substring replacement to mask letters (e.g. MG01 -> #01, Tata02 -> #02)
                            substring_pattern = re.compile(re.escape(term), re.IGNORECASE)
                            masked_val = substring_pattern.sub("#", masked_val)
                                
                    return masked_val
                
                # Process columns
                for col in remaining_cols:
                    # Apply masking cell-by-cell without pre-casting the whole column (preserves nulls correctly)
                    sanitized_df[col] = sanitized_df[col].apply(mask_cell)
                    
                elapsed_time = time.time() - start_time
                
                st.success(f"Processing Completed! Sanitized successfully in {elapsed_time:.3f} seconds.")
                
                st.divider()
                
                # Review & Export Section
                st.subheader("4. Review & Secure Export")
                
                # Display masked data preview
                with st.expander("View Masked Data Preview (First 5 Rows)", expanded=True):
                    st.dataframe(sanitized_df.head(5), use_container_width=True)
                    
                # Prepare CSV data in-memory to prevent saving sensitive files to the server disk
                csv_buffer = io.StringIO()
                sanitized_df.to_csv(csv_buffer, index=False)
                csv_bytes = csv_buffer.getvalue().encode('utf-8')
                
                # Premium secure export button
                st.download_button(
                    label="Download Sanitized CSV File",
                    data=csv_bytes,
                    file_name=f"sanitized_{file_name}",
                    mime="text/csv",
                    use_container_width=True
                )
                
    except Exception as err:
        st.error(f"An error occurred while reading or processing the file: {str(err)}")
        st.exception(err)
        
else:
    st.info("To start sanitizing corporate datasets, please upload a valid CSV or Excel spreadsheet using the uploader above.")
