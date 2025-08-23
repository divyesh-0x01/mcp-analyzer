from __future__ import annotations
from typing import Dict, List, Tuple
from .constants import DANGEROUS_PATTERNS, COMMON_CMD_KEYS, PROMPT_INJECTION_PATTERNS

def static_classify(name: str, description: str, raw_tool: Dict) -> Tuple[str, List[str]]:
    text = f"{name} {description}".lower()
    matches: List[str] = []
    score = 0
    for cat, pats in DANGEROUS_PATTERNS.items():
        for p in pats:
            if p in text:
                matches.append(f"{cat}:{p}")
                score += 2 if cat in ("file_ops", "exec", "secrets", "admin") else 1
    schema = (raw_tool or {}).get("inputSchema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    for p_name, p_spec in props.items():
        p_text = f"{p_name} {(p_spec.get('description') or '')}".lower() if isinstance(p_spec, dict) else str(p_spec).lower()
        if any(k in p_name.lower() for k in ("path", "paths", "filepath", "filename")):
            matches.append("file_ops:parameter"); score += 2
        if "read" in p_text or "file" in p_text:
            matches.append("file_ops:desc"); score += 1
        if p_name.lower() in [*COMMON_CMD_KEYS, "command"]:
            matches.append("exec:parameter"); score += 2
        if any(w in p_text for w in ("bash", "shell", "exec", "command", "subprocess", "system")):
            matches.append("exec:desc"); score += 2
    if score >= 4:    return "dangerous", matches
    if score >= 2:    return "suspicious", matches
    return "safe", matches

def detect_prompt_injection(description: str) -> Tuple[bool, List[str]]:
    """
    Detect prompt injection patterns in tool descriptions.
    
    Args:
        description: The tool description to analyze
        
    Returns:
        Tuple of (has_injection, detected_patterns)
    """
    if not description:
        return False, []
    
    description_lower = description.lower()
    detected_patterns = []
    
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in description_lower:
            detected_patterns.append(pattern)
    
    return len(detected_patterns) > 0, detected_patterns
