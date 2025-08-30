from __future__ import annotations
from typing import Dict, List, Tuple
from .constants import DANGEROUS_PATTERNS, COMMON_CMD_KEYS, PROMPT_INJECTION_PATTERNS

def detect_malicious_server_behavior(name: str, description: str, suspicious_behaviors: List[Dict] = None) -> Tuple[bool, List[str]]:
    """
    Detect malicious server behavior where tools execute dangerous operations without honestly describing their capabilities.
    
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
    
    # Check if tool description honestly mentions execution capabilities
    honest_execution_keywords = [
        "execute", "command", "system", "bash", "shell", "terminal", "process",
        "run", "launch", "start", "invoke", "call", "exec", "subprocess",
        "read", "write", "file", "directory", "create", "list", "move", "search",
        "metadata", "info", "tree", "path", "content", "contents", "access"
    ]
    
    dangerous_indicators = [
        "command executed", "shell access", "uid=", "gid=", "groups=",
        "user:", "hostname:", "system:", "root:", "whoami", "pwd",
        "process", "subprocess", "os.system", "eval(", "exec("
    ]
    
    # Check if description honestly mentions execution capabilities
    has_honest_execution_description = any(keyword in description_lower for keyword in honest_execution_keywords)
    
    # Check if any suspicious behavior contains dangerous indicators
    has_dangerous_behavior = False
    for behavior in suspicious_behaviors:
        response = behavior.get('response', '').lower()
        if any(indicator in response for indicator in dangerous_indicators):
            has_dangerous_behavior = True
            detected_patterns.append(f"dangerous_behavior:{name}")
            break
    
    # If tool executes dangerous operations but doesn't honestly describe its capabilities, it's a malicious server
    if has_dangerous_behavior and not has_honest_execution_description:
        detected_patterns.append("rogue_server:capability_mismatch")
        return True, detected_patterns
    
    return False, detected_patterns

def static_classify(name: str, description: str, raw_tool: Dict, suspicious_behaviors: List[Dict] = None) -> Tuple[str, List[str]]:
    """
    Classifies tools based on probe results and suspicious behaviors.
    Returns a tuple of (risk_level, matches) where risk_level is one of:
    - critical: For tool poisoning, command execution, or other critical issues
    - high: For multiple suspicious behaviors
    - medium: For a single suspicious behavior
    - safe: No issues detected
    """
    matches: List[str] = []
    
    # Only classify based on actual suspicious behaviors found by probes
    if suspicious_behaviors and len(suspicious_behaviors) > 0:
        # First, check for tool poisoning
        is_malicious, malicious_patterns = detect_malicious_server_behavior(name, description, suspicious_behaviors)
        if is_malicious:
            matches.extend(malicious_patterns)
            # Check if this is specifically a tool poisoning case
            if any('rogue_server:description_mismatch' in p for p in malicious_patterns):
                matches.append('tool_poisoning:detected')
            return "critical", matches
            
        # Check for direct evidence of tool poisoning in probe results
        for behavior in suspicious_behaviors:
            if isinstance(behavior, dict) and behavior.get('is_tool_poisoning'):
                matches.append('tool_poisoning:detected')
                return "critical", matches
        
        # Check for critical behaviors (command execution, file read, etc.)
        has_critical_behavior = False
        for behavior in suspicious_behaviors:
            # Check if this is a critical behavior
            behavior_str = str(behavior).lower()
            if any(critical_indicator in behavior_str for critical_indicator in [
                'root:', 'whoami', 'command output', 'uid=', 'gid=', 'shell access',
                '/etc/passwd', '/etc/shadow', 'daemon:', 'bin/', 'nologin',
                'tool poisoning', 'malicious_behavior', 'rogue_server',
                'inconsistent behavior', 'suspicious behavior', 'rogue behavior'
            ]):
                has_critical_behavior = True
                if any(x in behavior_str for x in ['rogue_server', 'malicious_behavior', 'tool poisoning']):
                    matches.append('tool_poisoning:detected')
                break
        
        # If we have any tool poisoning indicators, always return critical
        if 'tool_poisoning:detected' in matches:
            return "critical", matches
            
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
