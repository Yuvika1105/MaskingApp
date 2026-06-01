# app/data_masking/masking_engine.py
import re
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from app.data_masking.masking_policy import MaskingPolicy
from app.data_masking.custom_recognizers import (
    EnterpriseBrandRecognizer,
    EnterpriseModelRecognizer,
    EnterpriseMaterialRecognizer,
    CustomPhoneRecognizer,
    CustomNameRecognizer
)

# Core Helper for Masking Strategies
def apply_masking_strategy(value: str, strategy: str, entity_type: str = "PII", custom_constant: Optional[str] = None) -> str:
    if not isinstance(value, str):
        value = str(value)
    if not value or not value.strip():
        return value
        
    val_str = value.strip()
    
    if strategy == "No Masking":
        return value
        
    elif strategy == "Redaction":
        return f"<{entity_type}>"
        
    elif strategy == "Hashing":
        h = hashlib.sha256(val_str.encode("utf-8")).hexdigest()[:8].upper()
        return f"[HASH_{entity_type}_{h}]"
        
    elif strategy == "Custom Constant":
        return custom_constant if custom_constant else "[REDACTED]"
        
    elif strategy == "Character Masking":
        if "@" in val_str:  # email address
            parts = val_str.split("@")
            username = parts[0]
            domain = parts[1]
            if len(username) <= 2:
                masked_username = "*" * len(username)
            else:
                masked_username = username[0] + "*" * (len(username) - 2) + username[-1]
            return f"{masked_username}@{domain}"
        elif len(val_str) <= 3:
            return "*" * len(val_str)
        elif val_str.replace("+", "").replace("-", "").replace(" ", "").isdigit() and len(val_str) >= 7:  # phone
            return val_str[:3] + "*" * (len(val_str) - 5) + val_str[-2:]
        else:
            return val_str[0] + "*" * (len(val_str) - 2) + val_str[-1]
            
    return f"<{entity_type}>"


@dataclass
class MaskedSpan:
    start: int
    end: int
    entity_type: str
    score: float
    text: str


@dataclass
class MaskingResult:
    masked_text: str
    entity_count: int
    entities_found: Dict[str, int]


class MaskingEngine:
    def __init__(self, policy: MaskingPolicy, custom_rules: Optional[List[Dict[str, str]]] = None):
        self.policy = policy

        # Initialize Presidio for PII
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()
        
        # Load brand, model, material details from domain_config if available
        domain_config = policy.domain_config or {}
        brand_name = domain_config.get("brand_name", "MG")
        models = domain_config.get("models", ["ASTOR", "HECTOR", "HECTOR PLUS", "GLOSTER", "ZS EV", "COMET EV", "WINDSOR EV", "CLOUD EV", "MAJESTOR", "CYBERSTER", "M9"])
        material_regex = domain_config.get("material_code_regex", r"\b\d{4}[A-Z]{3}\b")
        
        # Find which entity rules correspond to brand, model, and material in policy rules
        brand_entity = "BRAND"
        model_entity = "MODEL"
        material_entity = "MATERIAL"
        for rule in policy.entity_rules:
            if "BRAND" in rule:
                brand_entity = rule
            elif "MODEL" in rule:
                model_entity = rule
            elif "MATERIAL" in rule or "PRODUCT" in rule:
                material_entity = rule
                
        # Register generalized custom recognizers
        registry.add_recognizer(EnterpriseBrandRecognizer(brand_name=brand_name, supported_entity=brand_entity))
        registry.add_recognizer(EnterpriseModelRecognizer(brand_name=brand_name, models=models, supported_entity=model_entity))
        registry.add_recognizer(EnterpriseMaterialRecognizer(regex_pattern=material_regex, supported_entity=material_entity))
        
        registry.add_recognizer(CustomPhoneRecognizer())
        registry.add_recognizer(CustomNameRecognizer())

        # Configure NLP engine to use en_core_web_sm explicitly
        spacy_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
        }
        nlp_provider = NlpEngineProvider(nlp_configuration=spacy_config)
        nlp_engine = nlp_provider.create_engine()

        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)

        # Register dynamic user-specified custom rules (domain-specific)
        if custom_rules:
            for rule in custom_rules:
                name = rule.get("name", "CUSTOM")
                rule_type = rule.get("type", "Keywords List")
                val = rule.get("value", "")
                if val:
                    self.add_dynamic_recognizer(name, rule_type, val)

        # Standard entities to scan
        self.presidio_entities = list(self.policy.entity_rules)
        if custom_rules:
            for rule in custom_rules:
                r_name = rule.get("name")
                if r_name and r_name not in self.presidio_entities:
                    self.presidio_entities.append(r_name)

    def add_dynamic_recognizer(self, name: str, rule_type: str, value: str):
        from presidio_analyzer import PatternRecognizer, Pattern
        if rule_type == "Regex Pattern":
            pattern = Pattern(name=f"custom_pat_{name}", regex=value, score=0.85)
            recognizer = PatternRecognizer(supported_entity=name, patterns=[pattern])
            self.analyzer.registry.add_recognizer(recognizer)
        elif rule_type == "Keywords List":
            keywords = [k.strip() for k in value.split(",") if k.strip()]
            recognizer = PatternRecognizer(supported_entity=name, deny_list=keywords)
            self.analyzer.registry.add_recognizer(recognizer)

    def get_model_recognizer(self, entity_type: str) -> Optional[EnterpriseModelRecognizer]:
        for rec in self.analyzer.registry.recognizers:
            if isinstance(rec, EnterpriseModelRecognizer) and rec.supported_entity == entity_type:
                return rec
        return None

    def get_brand_recognizer(self, entity_type: str) -> Optional[EnterpriseBrandRecognizer]:
        for rec in self.analyzer.registry.recognizers:
            if isinstance(rec, EnterpriseBrandRecognizer) and rec.supported_entity == entity_type:
                return rec
        return None

    def _detect_mg_brand_spans(self, text: str) -> List[MaskedSpan]:
        rec = self.get_brand_recognizer("MG_BRAND")
        if not rec:
            rec = EnterpriseBrandRecognizer(brand_name="MG", supported_entity="MG_BRAND")
        return self._detect_custom_spans(text, rec)

    def _detect_mg_model_spans(self, text: str) -> List[MaskedSpan]:
        rec = self.get_model_recognizer("MG_MODEL")
        if not rec:
            from app.data_masking.custom_recognizers import ModelLineRecognizer
            rec = ModelLineRecognizer()
        return self._detect_custom_spans(text, rec)

    def _detect_custom_spans(self, text: str, recognizer) -> List[MaskedSpan]:
        spans = []
        for pattern in recognizer.patterns:
            regex = re.compile(pattern.regex, re.IGNORECASE)
            for match in regex.finditer(text):
                spans.append(
                    MaskedSpan(
                        start=match.start(),
                        end=match.end(),
                        entity_type=recognizer.supported_entity,
                        score=pattern.score,
                        text=match.group()
                    )
                )
        return spans

    def mask_text(
        self, 
        text: str, 
        entity_strategies: Optional[Dict[str, str]] = None, 
        custom_constants: Optional[Dict[str, str]] = None
    ) -> MaskingResult:
        if not isinstance(text, str):
            text = str(text)
        if not text or not text.strip():
            return MaskingResult(text, 0, {})

        entity_strategies = entity_strategies or {}
        custom_constants = custom_constants or {}

        # Default strategy is Redaction for everything unless overridden
        all_spans: List[MaskedSpan] = []

        # 1. Detect custom brands and models (fallback if present in entity rules list)
        brand_entities = []
        model_entities = []
        
        for rec in self.analyzer.registry.recognizers:
            if isinstance(rec, EnterpriseBrandRecognizer):
                brand_entities.append(rec.supported_entity)
                if rec.supported_entity in self.presidio_entities:
                    all_spans.extend(self._detect_custom_spans(text, rec))
            elif isinstance(rec, EnterpriseModelRecognizer):
                model_entities.append(rec.supported_entity)
                if rec.supported_entity in self.presidio_entities:
                    all_spans.extend(self._detect_custom_spans(text, rec))

        # 2. Run Presidio Analyzer for PII and dynamic recognizers
        scan_entities = [e for e in self.presidio_entities if e not in brand_entities and e not in model_entities]
        if scan_entities:
            presidio_results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=scan_entities,
                score_threshold=0.4
            )
            for res in presidio_results:
                all_spans.append(
                    MaskedSpan(
                        start=res.start,
                        end=res.end,
                        entity_type=res.entity_type,
                        score=res.score,
                        text=text[res.start:res.end]
                    )
                )

        # 3. Add Safety Net regexes for Phone, CC, SSN if not already captured
        ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        for match in ssn_pattern.finditer(text):
            all_spans.append(MaskedSpan(match.start(), match.end(), "US_SSN", 1.0, match.group()))

        cc_pattern = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
        for match in cc_pattern.finditer(text):
            all_spans.append(MaskedSpan(match.start(), match.end(), "CREDIT_CARD", 1.0, match.group()))

        # 4. Resolve Overlaps (greedy selection: sort by start ascending, then length descending)
        all_spans = sorted(all_spans, key=lambda x: (x.start, -(x.end - x.start)))
        resolved_spans: List[MaskedSpan] = []
        current_end = -1
        for span in all_spans:
            if span.start >= current_end:
                resolved_spans.append(span)
                current_end = span.end

        # 5. Apply strategies in reverse order to maintain index accuracy
        entities_found = {}
        resolved_spans = sorted(resolved_spans, key=lambda x: x.start, reverse=True)
        
        for span in resolved_spans:
            strategy = entity_strategies.get(span.entity_type, "Redaction")
            custom_constant = custom_constants.get(span.entity_type, None)

            # Special pre-processing rule: if strategy is Redaction for a model entity, abbreviate it!
            model_rec = self.get_model_recognizer(span.entity_type)
            if model_rec and strategy == "Redaction":
                replacement = model_rec.abbreviate(span.text)
            else:
                replacement = apply_masking_strategy(
                    span.text, 
                    strategy, 
                    span.entity_type, 
                    custom_constant
                )

            text = text[:span.start] + replacement + text[span.end:]
            entities_found[span.entity_type] = entities_found.get(span.entity_type, 0) + 1

        return MaskingResult(text, sum(entities_found.values()), entities_found)

    def mask_value(
        self, 
        column_name: str, 
        value: str, 
        strategy: str = "Redaction", 
        custom_constant: Optional[str] = None
    ) -> str:
        if not value or not isinstance(value, str):
            return str(value)

        # Fallback to column rules in policy if strategy is not explicit
        target_entity = self.policy.column_rules.get(column_name, "PII")
        
        # Apply strategy directly on the cell content
        model_rec = self.get_model_recognizer(target_entity)
        
        if strategy == "Redaction" and model_rec:
            return model_rec.abbreviate(value)
        elif strategy == "Redaction" and target_entity in self.policy.replacement_map:
            # If standard replacement map has a mapped replacement, return it
            return self.policy.replacement_map[target_entity]
            
        return apply_masking_strategy(value, strategy, target_entity, custom_constant)
