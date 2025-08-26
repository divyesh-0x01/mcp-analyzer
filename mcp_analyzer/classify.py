from __future__ import annotations
from typing import Dict, List, Tuple
from .constants import DANGEROUS_PATTERNS, COMMON_CMD_KEYS, PROMPT_INJECTION_PATTERNS

def detect_malicious_server_behavior(name: str, description: str, suspicious_behaviors: List[Dict] = None) -> Tuple[bool, List[str]]:
    """
    Detect malicious server behavior where tools have innocent descriptions but execute dangerous operations.
    
    Args:
        name: Tool name
        description: Tool description
        suspicious_behaviors: List of suspicious behaviors detected during testing
        
    Returns:
        Tuple of (is_malicious, detected_patterns)
    """
    if not suspicious_behaviors:
        return False, []
    
    description_lower = description.lower()
    detected_patterns = []
    
    # Check if tool has innocent description but shows malicious behavior
    innocent_keywords = [
        "hello", "greeting", "message", "simple", "basic", "add", "sum", "calculate", 
        "multiply", "divide", "subtract", "math", "number", "text", "string", "format",
        "display", "show", "print", "return", "echo", "say", "tell", "inform"
    ]
    
    malicious_indicators = [
        "tool poisoning detected", "user:", "home directory:", "hostname:", 
        "system:", "darwin", "linux", "windows", "root:", "admin:", "privilege:",
        "command executed", "system command", "shell access", "file access",
        "network access", "database access", "credential", "password", "token"
    ]
    
    # Check if description suggests innocent behavior
    has_innocent_description = any(keyword in description_lower for keyword in innocent_keywords)
    
    # Check if any suspicious behavior contains malicious indicators
    has_malicious_behavior = False
    for behavior in suspicious_behaviors:
        response = behavior.get('response', '').lower()
        if any(indicator in response for indicator in malicious_indicators):
            has_malicious_behavior = True
            detected_patterns.append(f"malicious_behavior:{name}")
            break
    
    # If tool claims to be innocent but behaves maliciously, it's a malicious server
    if has_innocent_description and has_malicious_behavior:
        detected_patterns.append("rogue_server:description_mismatch")
        return True, detected_patterns
    
    return False, detected_patterns

def static_classify(name: str, description: str, raw_tool: Dict, suspicious_behaviors: List[Dict] = None) -> Tuple[str, List[str]]:
    text = f"{name} {description}".lower()
    matches: List[str] = []
    score = 0
    
    # Check for malicious server behavior first
    is_malicious, malicious_patterns = detect_malicious_server_behavior(name, description, suspicious_behaviors)
    if is_malicious:
        matches.extend(malicious_patterns)
        score += 10  # Very high score for malicious server behavior
    
    # Standard pattern matching
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
    
    # Adjusted scoring for malicious server detection
    if score >= 10:   return "critical", matches  # Malicious server behavior
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
