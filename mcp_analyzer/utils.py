from typing import Any, Dict, Optional, Union

def extract_result_text(result: Any) -> str:
    """Extract text from different result formats."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        # Try common response formats
        if 'text' in result:
            return result['text']
        if 'result' in result:
            return str(result['result'])
        if 'data' in result:
            return str(result['data'])
        # Fall back to string representation
        return str(result)
    return str(result)

def looks_like_passwd(text: str) -> bool:
    """Check if the text looks like a password file entry."""
    if not text or not isinstance(text, str):
        return False
    
    lines = text.strip().split('\n')
    if not lines:
        return False
    
    # Check if most lines match the format of /etc/passwd
    passwd_like_lines = 0
    for line in lines[:10]:  # Check first 10 lines to be efficient
        parts = line.split(':')
        if len(parts) >= 7:  # /etc/passwd has 7 fields
            passwd_like_lines += 1
    
    # If more than half the checked lines look like passwd entries
    return passwd_like_lines / min(10, len(lines)) > 0.5
