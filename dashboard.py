# dashboard.py
import io
import time
import json
import pandas as pd
import streamlit as st
import plotly.express as px
from pathlib import Path

# App imports
from config import DEFAULT_POLICY_PATH, POLICIES_DIR
from app.data_masking.masking_policy import MaskingPolicy
from app.data_masking.masking_engine import MaskingEngine
from app.data_masking.file_processors import FileProcessor

# Premium Page Config
st.set_page_config(
    page_title="SafeGuard — Dynamic Data Masking Hub",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Custom Styling (Harmonious sleek design, typography, side-by-side spacing, glassmorphic accents)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Plus+Jakarta+Sans:wght@300;400;500;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    .main-title {
        font-family: 'Outfit', sans-serif;
        font-size: 3rem !important;
        font-weight: 800;
        background: linear-gradient(135deg, #3b82f6, #8b5cf6, #ec4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.1rem;
        text-align: center;
    }
    
    .main-subtitle {
        font-size: 1.2rem !important;
        color: #6b7280;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    /* Premium card glassmorphism */
    .premium-card {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 1.5rem;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        margin-bottom: 1.5rem;
    }
    
    /* Highlighting replacements */
    .masked-span-redact {
        background-color: #fee2e2;
        color: #dc2626;
        padding: 2px 6px;
        border-radius: 4px;
        border: 1px solid #fca5a5;
        font-weight: 600;
        font-family: monospace;
    }
    .masked-span-hash {
        background-color: #f3e8ff;
        color: #7c3aed;
        padding: 2px 6px;
        border-radius: 4px;
        border: 1px solid #d8b4fe;
        font-weight: 600;
        font-family: monospace;
    }
    .masked-span-char {
        background-color: #fef3c7;
        color: #d97706;
        padding: 2px 6px;
        border-radius: 4px;
        border: 1px solid #fde68a;
        font-weight: 600;
        font-family: monospace;
    }
    .masked-span-const {
        background-color: #ecfdf5;
        color: #059669;
        padding: 2px 6px;
        border-radius: 4px;
        border: 1px solid #a7f3d0;
        font-weight: 600;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session States
if "masking_history" not in st.session_state:
    st.session_state.masking_history = []


# Helper to convert YAML engine configuration with dynamic user-defined custom rules
@st.cache_resource(show_spinner=False)
def load_masking_engine(policy_path: str, custom_rules_json: str) -> MaskingEngine:
    policy = MaskingPolicy.from_yaml(policy_path)
    rules = json.loads(custom_rules_json) if custom_rules_json else None
    return MaskingEngine(policy, custom_rules=rules)


# Main layout
st.markdown('<div class="main-title">🛡️ SafeGuard</div>', unsafe_allow_html=True)
st.markdown('<div class="main-subtitle">Dynamic Data Masking & Sensitivity Diagnostics Dashboard</div>', unsafe_allow_html=True)

# Initialize session state for custom rules if not present
if "custom_rules" not in st.session_state:
    st.session_state.custom_rules = []

# ----------------- SIDEBAR CONFIGURATION -----------------
with st.sidebar:
    st.header("⚙️ Configuration Hub")
    
    # 1. Masking Policy choice - scan POLICIES_DIR dynamically for all yaml files
    policy_files = sorted(list(POLICIES_DIR.glob("*.yaml")))
    policy_options = []
    policy_path_map = {}
    
    for pf in policy_files:
        if pf.name == "default_policy.yaml":
            label = "Standard PII Only (default)"
        elif pf.name == "mg_policy.yaml":
            label = "MG Motors Enterprise Data"
        else:
            name_clean = pf.stem.replace("_", " ").title()
            label = f"{name_clean} Enterprise Data"
        policy_options.append(label)
        policy_path_map[label] = pf
        
    policy_choice = st.radio(
        "Select Base Policy Mode",
        options=policy_options,
        index=0 if "Standard PII Only (default)" in policy_options else 0,
        help="Choose a pre-defined or custom data masking policy configuration."
    )
    
    policy_path = policy_path_map[policy_choice]
    
    # Convert custom rules to hashable JSON string for cached resource loader
    custom_rules_json = json.dumps(st.session_state.custom_rules)
    engine = load_masking_engine(str(policy_path), custom_rules_json)
    
    st.info(f"Loaded `{Path(policy_path).name}` base policy rules.")

    st.markdown("---")
    
    # 2. Dynamic Custom Recognizers Expander
    with st.expander("🛠️ Dynamic Custom Recognizers", expanded=True):
        st.markdown("<small>Define bespoke keywords or patterns to dynamically scan and mask.</small>", unsafe_allow_html=True)
        
        # Preset templates
        policy_brand = engine.policy.domain_config.get("brand_name", "Enterprise")
        preset_options = ["Clean Slate", f"{policy_brand} Motors Custom Preset" if policy_brand != "Enterprise" else "Enterprise Custom Preset"]
        
        preset_template = st.selectbox(
            "Load Preset Template",
            preset_options
        )
        
        if "prev_preset" not in st.session_state:
            st.session_state.prev_preset = "Clean Slate"
            
        if st.session_state.prev_preset not in preset_options:
            st.session_state.prev_preset = "Clean Slate"
            
        if preset_template != st.session_state.prev_preset:
            if preset_template != "Clean Slate":
                domain_config = engine.policy.domain_config
                brand_name = domain_config.get("brand_name", "Enterprise")
                models = domain_config.get("models", [])
                material_regex = domain_config.get("material_code_regex", r"\b\d{4}[A-Z]{3}\b")
                
                # Dynamically construct custom rules based on the active policy's domain_config
                st.session_state.custom_rules = [
                    {
                        "name": f"{brand_name.upper()}_BRAND", 
                        "type": "Regex Pattern", 
                        "value": rf"\b{brand_name}\s+Motors?\b|\b{brand_name}\s+[A-Z0-9\-]+\b|\b{brand_name}\b"
                    },
                    {
                        "name": f"{brand_name.upper()}_MODEL", 
                        "type": "Keywords List", 
                        "value": ", ".join(models)
                    },
                    {
                        "name": f"{brand_name.upper()}_MATERIAL", 
                        "type": "Regex Pattern", 
                        "value": material_regex
                    }
                ]
            else:
                st.session_state.custom_rules = []
            st.session_state.prev_preset = preset_template
            st.rerun()
            
        # Form to add custom recognizer
        with st.form("custom_recognizer_form", clear_on_submit=True):
            r_name = st.text_input("Entity Name", placeholder="e.g., PRODUCT_ID").strip().upper().replace(" ", "_")
            r_type = st.selectbox("Detection Type", ["Keywords List", "Regex Pattern"])
            r_val = st.text_area(
                "Value", 
                placeholder="Keywords: comma-separated list\nRegex: e.g. \\b\\d{3}-[A-Z]{2}\\b"
            )
            add_rule_btn = st.form_submit_button("Add Recognizer")
            
            if add_rule_btn and r_name and r_val:
                new_rule = {"name": r_name, "type": r_type, "value": r_val.strip()}
                # Check duplicate
                st.session_state.custom_rules = [r for r in st.session_state.custom_rules if r["name"] != r_name]
                st.session_state.custom_rules.append(new_rule)
                st.toast(f"Registered `{r_name}` recognizer!", icon="✔️")
                st.rerun()
                
        # List of added custom recognizers
        if st.session_state.custom_rules:
            st.markdown("<small><b>Active Custom Recognizers:</b></small>", unsafe_allow_html=True)
            for idx, rule in enumerate(st.session_state.custom_rules):
                rc1, rc2 = st.columns([4, 1])
                rc1.markdown(f"<small>🏷️ <b>{rule['name']}</b> ({rule['type'].split()[0]})</small>", unsafe_allow_html=True)
                if rc2.button("🗑️", key=f"del_rule_{idx}"):
                    st.session_state.custom_rules.pop(idx)
                    st.rerun()

    st.markdown("---")
    
    st.subheader("📝 Manual Redaction Rules")
    custom_words_input = st.text_input(
        "Redact custom specific words (comma-separated)",
        placeholder="e.g., Confidential, SecretCode, ProjectX"
    )
    custom_words_list = [w.strip() for w in custom_words_input.split(",") if w.strip()] if custom_words_input else []
    
    if custom_words_list:
        st.success(f"Configured {len(custom_words_list)} custom words for direct redaction.")

    st.markdown("---")
    st.caption("Developed by Antigravity AI. Fully Local & Secure.")

# ----------------- MAIN CONTROL TABS -----------------
tab_upload, tab_config, tab_preview, tab_analytics = st.tabs([
    "📥 1. Upload Document", 
    "⚙️ 2. Dynamic Configuration", 
    "👁️ 3. Comparative Preview", 
    "📈 4. Diagnostic Analytics"
])

# Global file upload state
uploaded_file = st.session_state.get("uploaded_file_data", None)

with tab_upload:
    st.subheader("Upload Document for Sensitivity Assessment")
    st.markdown("Upload structural data (CSV, Excel) or unstructured texts (PDF, Word, TXT, JSON) to start scanning.")
    
    u_file = st.file_uploader(
        "Select File", 
        type=["csv", "xlsx", "xls", "pdf", "docx", "txt", "json"],
        key="file_uploader_key"
    )
    
    if u_file is not None:
        st.session_state.uploaded_file_data = u_file
        uploaded_file = u_file
        st.success(f"Successfully loaded file: `{uploaded_file.name}` ({len(uploaded_file.getvalue())} bytes)")
    else:
        st.info("Please select and upload a document to proceed to sensitivity mapping.")

# ----------------- SCAN & CONFIGURATION LOGIC -----------------
if uploaded_file is not None:
    file_name = uploaded_file.name
    file_bytes = uploaded_file.getvalue()
    suffix = Path(file_name).suffix.lower()
    
    is_tabular = suffix in [".csv", ".xlsx", ".xls"]
    
    # Cache scanning so it runs only once per uploaded file
    if "last_scanned_file" not in st.session_state or st.session_state.last_scanned_file != file_name:
        with st.spinner("Analyzing document structure & detecting sensitive entities..."):
            if is_tabular:
                # Tabular analysis
                if suffix == ".csv":
                    df_raw = pd.read_csv(io.BytesIO(file_bytes))
                else:
                    df_raw = pd.read_excel(io.BytesIO(file_bytes))
                
                st.session_state.df_raw = df_raw
                
                # Auto-detect PII entities per column by scanning first 15 rows
                detected_cols = {}
                for col in df_raw.columns:
                    col_data = df_raw[col].dropna().astype(str).tolist()[:15]
                    col_text = " ".join(col_data)
                    scan_res = engine.mask_text(col_text)
                    
                    # Find highest occurrence entity
                    if scan_res.entities_found:
                        best_entity = max(scan_res.entities_found, key=scan_res.entities_found.get)
                        detected_cols[col] = best_entity
                    else:
                        # Check policy mapped column names
                        policy_mapped = engine.policy.column_rules.get(col)
                        if policy_mapped:
                            detected_cols[col] = policy_mapped
                        else:
                            detected_cols[col] = "None"
                
                st.session_state.detected_cols = detected_cols
                st.session_state.selected_columns = [col for col, ent in detected_cols.items() if ent != "None"]
                
                # Default strategies
                st.session_state.column_strategies = {col: "Redaction" for col in df_raw.columns}
                st.session_state.column_constants = {col: "" for col in df_raw.columns}
                
            else:
                # Unstructured analysis
                if suffix == ".txt":
                    raw_text = file_bytes.decode("utf-8", errors="ignore")
                elif suffix == ".json":
                    raw_text = file_bytes.decode("utf-8", errors="ignore")
                    try:
                        # Pretty print
                        raw_text = json.dumps(json.loads(raw_text), indent=2)
                    except:
                        pass
                elif suffix == ".pdf":
                    extracted = []
                    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                        for page in pdf.pages:
                            text = page.extract_text()
                            if text: extracted.append(text)
                    raw_text = "\n".join(extracted)
                elif suffix == ".docx":
                    doc = Document(io.BytesIO(file_bytes))
                    raw_text = "\n".join([p.text for p in doc.paragraphs])
                
                st.session_state.raw_text = raw_text
                
                # Full scan
                scan_res = engine.mask_text(raw_text)
                st.session_state.scan_res = scan_res
                st.session_state.entity_strategies = {ent: "Redaction" for ent in scan_res.entities_found.keys()}
                st.session_state.entity_constants = {ent: "" for ent in scan_res.entities_found.keys()}
                st.session_state.selected_entities = list(scan_res.entities_found.keys())
            
            st.session_state.last_scanned_file = file_name
            st.session_state.masking_executed = False

    # ----------------- CONFIGURATION TAB -----------------
    with tab_config:
        st.subheader("Configure Sensitivity Constraints & Replacement Strategies")
        
        if is_tabular:
            df_raw = st.session_state.df_raw
            detected_cols = st.session_state.detected_cols
            
            st.markdown(f"📊 **Structure**: `{len(df_raw.columns)}` Columns detected, `{len(df_raw)}` total rows.")
            
            st.write("### Choose Columns and Strategies to Mask")
            
            # Interactive Grid layout for column strategies
            col_sel, col_name, col_pii, col_strat, col_const = st.columns([1, 3, 3, 3, 3])
            
            col_sel.write("**Apply Mask?**")
            col_name.write("**Column Name**")
            col_pii.write("**Auto-Detected Entity Class**")
            col_strat.write("**Masking Strategy**")
            col_const.write("**Custom replacement / Constant**")
            
            st.markdown("---")
            
            selected_cols = []
            column_strategies = {}
            column_constants = {}
            
            for i, col in enumerate(df_raw.columns):
                c_sel, c_name, c_pii, c_strat, c_const = st.columns([1, 3, 3, 3, 3])
                
                # Checkbox selection
                is_selected_default = col in st.session_state.selected_columns
                to_mask = c_sel.checkbox("Mask", value=is_selected_default, key=f"sel_{col}_{i}")
                
                c_name.markdown(f"**{col}**")
                
                # Display auto-detected entity type
                det_entity = detected_cols.get(col, "None")
                if det_entity != "None":
                    c_pii.warning(f"⚠️ {det_entity}")
                else:
                    c_pii.markdown("<span style='color: #6b7280;'>Clean / Low Risk</span>", unsafe_allow_html=True)
                
                # Strategy selector
                strategy = c_strat.selectbox(
                    "Strategy",
                    options=["Redaction", "Hashing", "Character Masking", "Custom Constant", "Free-Text Presidio"],
                    index=0 if det_entity != "None" else 4,
                    key=f"strat_{col}_{i}",
                    disabled=not to_mask
                )
                
                # Custom replacement constant
                const_val = c_const.text_input(
                    "Constant Text",
                    value="[REDACTED]" if strategy == "Custom Constant" else "",
                    key=f"const_{col}_{i}",
                    disabled=not (to_mask and strategy == "Custom Constant"),
                    label_visibility="collapsed"
                )
                
                if to_mask:
                    selected_cols.append(col)
                    column_strategies[col] = strategy
                    column_constants[col] = const_val
            
            # Row-level Filtering collapsible panel
            st.markdown("---")
            with st.expander("🔍 Advanced Row Filtering Conditions (Apply Masking Only to Specific Rows)"):
                st.markdown("If configured, masking will strictly apply only to rows satisfying the condition. Other rows remain completely raw.")
                rf_col = st.selectbox("Select Filter Column", ["None"] + list(df_raw.columns))
                
                if rf_col != "None":
                    rf_op = st.selectbox("Operator", ["Equals", "Contains", "Greater than", "Less than"])
                    rf_val = st.text_input("Filter Value")
                else:
                    rf_op, rf_val = None, None
            
            # Apply Masking Button
            st.markdown("---")
            apply_btn = st.button("🚀 Apply Dynamic Masking", type="primary")
            
            if apply_btn:
                with st.spinner("Executing dynamic column redactions..."):
                    start_time = time.time()
                    
                    df_masked = FileProcessor.process_csv(
                        file_bytes=file_bytes,
                        engine=engine,
                        column_strategies=column_strategies,
                        column_constants=column_constants,
                        selected_columns=selected_cols,
                        row_filter_col=rf_col if rf_col != "None" else None,
                        row_filter_op=rf_op,
                        row_filter_val=rf_val
                    )
                    
                    elapsed = time.time() - start_time
                    st.session_state.df_masked = df_masked
                    st.session_state.masking_executed = True
                    
                    # Generate audit summary
                    redacted_cells = 0
                    for col in selected_cols:
                        # count changed cells
                        redacted_cells += (df_raw[col].astype(str) != df_masked[col].astype(str)).sum()
                    
                    st.session_state.masking_metrics = {
                        "redacted_elements": int(redacted_cells),
                        "elapsed_seconds": elapsed,
                        "rows_count": len(df_raw),
                        "cols_count": len(df_raw.columns),
                        "file_size_bytes": len(file_bytes)
                    }
                    st.success("Masking Completed Successfully!")
                    st.toast("Masking Done! Check Preview Tab.", icon="🛡️")
                    
        else:
            # Unstructured text configurator
            raw_text = st.session_state.raw_text
            scan_res = st.session_state.scan_res
            
            st.markdown(f"📄 **Content Length**: `{len(raw_text)}` characters.")
            
            if not scan_res.entities_found:
                st.info("No sensitive PII or corporate entities were auto-detected. You can still use Custom Redactions in the sidebar.")
            
            st.write("### Choose Entity Types and Replacement Strategies")
            
            selected_ents = []
            entity_strategies = {}
            entity_constants = {}
            
            col_ent_sel, col_ent_name, col_ent_count, col_ent_strat, col_ent_const = st.columns([1, 3, 2, 3, 3])
            
            col_ent_sel.write("**Apply?**")
            col_ent_name.write("**Entity Type**")
            col_ent_count.write("**Occurrences**")
            col_ent_strat.write("**Strategy**")
            col_ent_const.write("**Replacement / Constant**")
            
            st.markdown("---")
            
            for i, (ent, count) in enumerate(scan_res.entities_found.items()):
                c_sel, c_name, c_cnt, c_strat, c_const = st.columns([1, 3, 2, 3, 3])
                
                is_selected_default = ent in st.session_state.selected_entities
                to_mask = c_sel.checkbox("Mask", value=is_selected_default, key=f"ent_sel_{ent}_{i}")
                
                c_name.markdown(f"**{ent}**")
                c_cnt.markdown(f"`{count}` matches")
                
                strategy = c_strat.selectbox(
                    "Strategy",
                    options=["Redaction", "Hashing", "Character Masking", "Custom Constant"],
                    key=f"ent_strat_{ent}_{i}",
                    disabled=not to_mask
                )
                
                const_val = c_const.text_input(
                    "Constant Text",
                    value="[REDACTED]" if strategy == "Custom Constant" else "",
                    key=f"ent_const_{ent}_{i}",
                    disabled=not (to_mask and strategy == "Custom Constant"),
                    label_visibility="collapsed"
                )
                
                if to_mask:
                    selected_ents.append(ent)
                    entity_strategies[ent] = strategy
                    entity_constants[ent] = const_val
            
            # Apply Button
            st.markdown("---")
            apply_btn = st.button("🚀 Apply Dynamic Redaction", type="primary")
            
            if apply_btn:
                with st.spinner("Processing unstructured document spans..."):
                    start_time = time.time()
                    
                    # Temporarily update engine entity rules to strictly only process the selected checked entities
                    original_rules = engine.policy.entity_rules
                    engine.policy.entity_rules = selected_ents
                    
                    # Process based on type
                    if suffix == ".docx":
                        masked_docx_bytes = FileProcessor.process_docx(
                            file_bytes, 
                            engine, 
                            entity_strategies, 
                            entity_constants
                        )
                        st.session_state.masked_docx_bytes = masked_docx_bytes
                        # Re-extract text for preview
                        doc_masked = Document(io.BytesIO(masked_docx_bytes))
                        masked_text = "\n".join([p.text for p in doc_masked.paragraphs])
                    elif suffix == ".pdf":
                        # PDFs are read-only format. We output masked text
                        masked_text = FileProcessor.process_pdf(
                            file_bytes, 
                            engine, 
                            entity_strategies, 
                            entity_constants
                        )
                    else:
                        masked_text = engine.mask_text(
                            raw_text, 
                            entity_strategies, 
                            entity_constants
                        ).masked_text
                    
                    # Post process manual custom words if any
                    if custom_words_list:
                        for word in custom_words_list:
                            # Replaces custom words with custom replacement
                            pattern = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
                            masked_text = pattern.sub("[REDACTED]", masked_text)
                    
                    elapsed = time.time() - start_time
                    
                    # Reset policy
                    engine.policy.entity_rules = original_rules
                    
                    st.session_state.masked_text = masked_text
                    st.session_state.masking_executed = True
                    
                    # Calculate entities count
                    metrics_res = engine.mask_text(raw_text, entity_strategies, entity_constants)
                    
                    st.session_state.masking_metrics = {
                        "redacted_elements": sum(metrics_res.entities_found.values()) + len(custom_words_list),
                        "elapsed_seconds": elapsed,
                        "char_count": len(raw_text),
                        "entity_counts": metrics_res.entities_found,
                        "file_size_bytes": len(file_bytes)
                    }
                    st.success("Document Redaction Completed!")
                    st.toast("Masking Done! Check Preview Tab.", icon="🛡️")

    # ----------------- PREVIEW & DOWNLOAD TAB -----------------
    with tab_preview:
        if not st.session_state.get("masking_executed", False):
            st.info("Please configure and apply masking in the 'Dynamic Configuration' tab to view results.")
        else:
            st.subheader("Interactive Before & After Verification")
            
            # Diagnostic Audit Summary Box
            metrics = st.session_state.masking_metrics
            st.markdown(f"""
            <div class="premium-card">
                <h3>📊 Diagnostics & Quality Audit</h3>
                <p>⚡ <b>Processing Speed</b>: {metrics['elapsed_seconds']:.4f} seconds</p>
                <p>🔒 <b>Masked Tokens / Cells</b>: {metrics['redacted_elements']} elements redacted</p>
                <p>📁 <b>File Name</b>: {file_name} ({metrics['file_size_bytes'] / 1024:.2f} KB)</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Side-by-side Comparative Panels
            if is_tabular:
                df_raw = st.session_state.df_raw
                df_masked = st.session_state.df_masked
                
                st.write("### Raw Data vs Anonymized Preview")
                
                # Apply highlighters comparing cells
                def highlight_diff(data):
                    attr = 'background-color: #fef3c7; border: 1px solid #fde68a; font-weight: bold;'
                    # Return styled dataframe
                    df_style = pd.DataFrame('', index=data.index, columns=data.columns)
                    for col in data.columns:
                        diff = df_raw[col].astype(str) != df_masked[col].astype(str)
                        df_style.loc[diff, col] = attr
                    return df_style
                
                col_left, col_right = st.columns(2)
                
                with col_left:
                    st.markdown("#### 📥 Original Raw DataFrame (First 8 rows)")
                    st.dataframe(df_raw.head(8), use_container_width=True)
                    
                with col_right:
                    st.markdown("#### 📤 Masked Anonymized DataFrame (First 8 rows)")
                    # Show styled preview showing exactly what changed highlighted in gold
                    styled_df = df_masked.head(8).style.apply(highlight_diff, axis=None)
                    st.dataframe(styled_df, use_container_width=True)
                    
                # CSV/Excel Exporter Layout
                st.markdown("---")
                st.write("### 💾 Export Redacted Spreadsheet")
                
                csv_bytes = df_masked.to_csv(index=False).encode("utf-8")
                
                # Create binary Excel writer
                excel_buffer = io.BytesIO()
                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                    df_masked.to_excel(writer, index=False)
                excel_bytes = excel_buffer.getvalue()
                
                exp_c1, exp_c2, exp_c3 = st.columns(3)
                
                exp_c1.download_button(
                    label="📥 Download as CSV Format",
                    data=csv_bytes,
                    file_name=f"{Path(file_name).stem}_anonymized.csv",
                    mime="text/csv",
                    use_container_width=True
                )
                
                exp_c2.download_button(
                    label="📥 Download as Excel Spreadsheet (XLSX)",
                    data=excel_bytes,
                    file_name=f"{Path(file_name).stem}_anonymized.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
                
                # Session Audit Log
                audit_report = {
                    "session_id": str(time.time()),
                    "timestamp": pd.Timestamp.now().isoformat(),
                    "file_name": file_name,
                    "row_count": len(df_raw),
                    "column_count": len(df_raw.columns),
                    "selected_columns": list(column_strategies.keys()),
                    "applied_strategies": column_strategies,
                    "applied_constants": {k: v for k, v in column_constants.items() if v},
                    "metrics": metrics
                }
                
                exp_c3.download_button(
                    label="📋 Download Audit Report (JSON)",
                    data=json.dumps(audit_report, indent=2),
                    file_name=f"{Path(file_name).stem}_masking_audit.json",
                    mime="application/json",
                    use_container_width=True
                )
                
            else:
                # Unstructured preview
                raw_text = st.session_state.raw_text
                masked_text = st.session_state.masked_text
                
                st.write("### Text Anonymization Compare")
                
                # Reconstruct text with HTML tag colors for visual highlight
                def format_highlights(text):
                    # Wrap token placeholders in pretty styled spans
                    # Redactions: <ENTITY_NAME>
                    text = re.sub(
                        r"(<([A-Z_]+)>)",
                        r'<span class="masked-span-redact">\1</span>',
                        text
                    )
                    # Hashing: [HASH_ENTITY_NAME_HASH]
                    text = re.sub(
                        r"(\[HASH_([A-Z_]+)_([A-Z0-9]+)\])",
                        r'<span class="masked-span-hash">\1</span>',
                        text
                    )
                    # Character: e.g. J***n
                    # We can target stars sequence
                    text = re.sub(
                        r"\b([A-Za-z0-9](?:\*+)[A-Za-z0-9])\b",
                        r'<span class="masked-span-char">\1</span>',
                        text
                    )
                    # Custom Constants: e.g. [REDACTED] or [CONFIDENTIAL]
                    text = re.sub(
                        r"(\[REDACTED\]|\[CONFIDENTIAL\])",
                        r'<span class="masked-span-const">\1</span>',
                        text
                    )
                    return text.replace("\n", "<br>")

                col_left, col_right = st.columns(2)
                
                with col_left:
                    st.markdown("#### 📥 Original Unstructured Document")
                    st.markdown(
                        f'<div style="height: 480px; overflow-y: auto; padding: 1rem; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; font-size: 0.95rem;">{raw_text.replace(chr(10), "<br>")}</div>', 
                        unsafe_allow_html=True
                    )
                    
                with col_right:
                    st.markdown("#### 📤 Redacted Comparative Preview")
                    highlighted_html = format_highlights(masked_text)
                    st.markdown(
                        f'<div style="height: 480px; overflow-y: auto; padding: 1rem; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; font-size: 0.95rem; background-color: #111827;">{highlighted_html}</div>', 
                        unsafe_allow_html=True
                    )
                
                # Exporter
                st.markdown("---")
                st.write("### 💾 Export Redacted Document")
                
                exp_c1, exp_c2, exp_c3 = st.columns(3)
                
                # Standard Text Export
                exp_c1.download_button(
                    label="📥 Download Masked Text (.TXT)",
                    data=masked_text.encode("utf-8"),
                    file_name=f"{Path(file_name).stem}_redacted.txt",
                    mime="text/plain",
                    use_container_width=True
                )
                
                # Word Document Export
                if suffix == ".docx":
                    docx_bytes = st.session_state.masked_docx_bytes
                    exp_c2.download_button(
                        label="📥 Download Re-encoded Word Doc (.DOCX)",
                        data=docx_bytes,
                        file_name=f"{Path(file_name).stem}_redacted.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True
                    )
                else:
                    # Create a basic Word document from text
                    doc_new = Document()
                    for paragraph in masked_text.split("\n"):
                        if paragraph.strip():
                            doc_new.add_paragraph(paragraph)
                    doc_io = io.BytesIO()
                    doc_new.save(doc_io)
                    
                    exp_c2.download_button(
                        label="📥 Download as Reconstructed Word Doc (.DOCX)",
                        data=doc_io.getvalue(),
                        file_name=f"{Path(file_name).stem}_redacted.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True
                    )
                
                # Audit log JSON
                audit_report = {
                    "session_id": str(time.time()),
                    "timestamp": pd.Timestamp.now().isoformat(),
                    "file_name": file_name,
                    "applied_strategies": entity_strategies,
                    "applied_constants": {k: v for k, v in entity_constants.items() if v},
                    "custom_words_redacted": custom_words_list,
                    "metrics": metrics
                }
                
                exp_c3.download_button(
                    label="📋 Download Audit Report (JSON)",
                    data=json.dumps(audit_report, indent=2),
                    file_name=f"{Path(file_name).stem}_masking_audit.json",
                    mime="application/json",
                    use_container_width=True
                )

    # ----------------- ANALYTICS TAB -----------------
    with tab_analytics:
        if not st.session_state.get("masking_executed", False):
            st.info("Please execute masking to view sensitivity diagnostics and visualization.")
        else:
            st.subheader("Diagnostic Sensitivity Visualization")
            
            metrics = st.session_state.masking_metrics
            
            if is_tabular:
                # Tabular metrics - show columns selected vs unmasked
                total_cols = metrics["cols_count"]
                masked_cols_count = len(column_strategies)
                clean_cols_count = total_cols - masked_cols_count
                
                chart_df = pd.DataFrame({
                    "Category": ["Masked Columns", "Clean Columns"],
                    "Count": [masked_cols_count, clean_cols_count]
                })
                
                c_left, c_right = st.columns(2)
                
                with c_left:
                    st.write("#### 📊 Spreadsheet Vulnerability Overview")
                    fig = px.pie(
                        chart_df, 
                        names="Category", 
                        values="Count", 
                        hole=0.4,
                        color_discrete_sequence=["#ef4444", "#10b981"]
                    )
                    fig.update_layout(margin=dict(t=10, b=10, l=10, r=10))
                    st.plotly_chart(fig, use_container_width=True)
                    
                with c_right:
                    st.write("#### 🛡️ Replacement Strategies Applied")
                    strat_counts = pd.Series(list(column_strategies.values())).value_counts()
                    fig_bar = px.bar(
                        x=strat_counts.index, 
                        y=strat_counts.values,
                        labels={"x": "Masking Strategy", "y": "Columns Applied"},
                        color=strat_counts.index,
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    st.plotly_chart(fig_bar, use_container_width=True)
            else:
                # Unstructured metrics
                entity_counts = metrics["entity_counts"]
                
                if not entity_counts:
                    st.info("No statistics available as no entities were redacted.")
                else:
                    c_left, c_right = st.columns(2)
                    
                    with c_left:
                        st.write("#### 📊 Sensitivity Entity Distribution")
                        ent_df = pd.DataFrame({
                            "Entity Type": list(entity_counts.keys()),
                            "Match Count": list(entity_counts.values())
                        })
                        fig = px.bar(
                            ent_df, 
                            x="Match Count", 
                            y="Entity Type", 
                            orientation="h",
                            color="Entity Type",
                            color_discrete_sequence=px.colors.sequential.Sunsetdark
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                    with c_right:
                        st.write("#### 🛡️ Dynamic Entity Strategies Map")
                        strat_df = pd.DataFrame({
                            "Entity": list(entity_strategies.keys()),
                            "Strategy": list(entity_strategies.values())
                        })
                        fig_pie = px.pie(
                            strat_df, 
                            names="Strategy", 
                            hole=0.4,
                            color_discrete_sequence=px.colors.qualitative.Safe
                        )
                        st.plotly_chart(fig_pie, use_container_width=True)
