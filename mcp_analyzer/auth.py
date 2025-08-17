from __future__ import annotations
from typing import Any, Dict, List, Tuple
from .constants import COMMON_AUTH_KEYS

def has_auth_env(server_env: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Returns (present, matched_keys) based ONLY on server-specific env from the config.
    Do NOT look at process-wide os.environ.
    """
    matched: List[str] = []
    if not server_env:
        return False, matched
    for k, v in server_env.items():
        if not v:  # empty/None isn't usable auth
            continue
        for a in COMMON_AUTH_KEYS:
            if a.lower() in k.lower():
                matched.append(k)
                break
    return bool(matched), matched
