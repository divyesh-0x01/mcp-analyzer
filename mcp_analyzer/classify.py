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
    """
    Simplified classification that only considers actual probe results.
    No more static keyword-based risk assessment.
    """
    matches: List[str] = []
    
    # Only classify based on actual suspicious behaviors found by probes
    if suspicious_behaviors and len(suspicious_behaviors) > 0:
        # Check for malicious server behavior (tool poisoning)
        is_malicious, malicious_patterns = detect_malicious_server_behavior(name, description, suspicious_behaviors)
        if is_malicious:
            matches.extend(malicious_patterns)
            return "critical", matches
        
        # If suspicious behaviors found but not malicious server, classify based on behavior severity
        # Check for critical behaviors first (command execution, file read, etc.)
        has_critical_behavior = False
        for behavior in suspicious_behaviors:
            # Check if this is a critical behavior
            if any(critical_indicator in str(behavior).lower() for critical_indicator in [
                'root:', 'whoami', 'command output', 'uid=', 'gid=', 'shell access',
                '/etc/passwd', '/etc/shadow', 'daemon:', 'bin/', 'nologin'
            ]):
                has_critical_behavior = True
                break
        
        if has_critical_behavior:
            return "critical", matches
        elif len(suspicious_behaviors) >= 2:
            return "high", matches
        else:
            return "medium", matches
    
    # No suspicious behaviors found - tool is safe
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
