from __future__ import annotations
import os, re, json, logging
from typing import Any, Dict, List, Optional, Callable, Awaitable, TypeVar
from dataclasses import dataclass
from enum import Enum
import asyncio
from . import call_tool_with_client
from .llm_fuzzer import generate_payloads
from .utils import extract_result_text, looks_like_passwd
from .constants import (
    COMMON_PATH_KEYS, COMMON_CMD_KEYS, COMMON_ARG_FOR_POSITIONAL,
    UNIX_SENSITIVE, WIN_SENSITIVE, BENIGN_CMD, BENIGN_CMD_ALT
)

# Type aliases
T = TypeVar('T')
ProbeFunction = Callable[[Any, Dict[str, Any], bool], Awaitable[Dict[str, Any]]]

class ProbeType(str, Enum):
    FILE_READ = "file_read"
    COMMAND_EXEC = "command_exec"
    API_ENDPOINT = "api_endpoint"
    AUTHENTICATION = "authentication"
    DATA_EXPOSURE = "data_exposure"

@dataclass
class ProbeResult:
    success: bool = False
    payload: Optional[Any] = None
    proof: Optional[str] = None
    response: Optional[Any] = None
    attempts: List[Dict[str, Any]] = None
    probe_type: Optional[ProbeType] = None
    severity: str = "info"
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "probe_type": str(self.probe_type) if self.probe_type else None,
            "severity": self.severity,
            "confidence": self.confidence,
            "payload": self.payload,
            "proof": self.proof,
            "response": self.response,
            "attempts": self.attempts or []
        }

# Registry of available probes
PROBE_REGISTRY: Dict[ProbeType, ProbeFunction] = {}

def register_probe(probe_type: ProbeType) -> Callable[[ProbeFunction], ProbeFunction]:
    """Decorator to register a probe function for a specific type."""
    def decorator(func: ProbeFunction) -> ProbeFunction:
        PROBE_REGISTRY[probe_type] = func
        return func
    return decorator

async def get_relevant_probes(tool: Dict[str, Any]) -> List[ProbeType]:
    """Determine which probes are relevant for a given tool based on its metadata."""
    probes = []
    tool_name = tool.get('name', '').lower()
    tool_desc = tool.get('description', '').lower()
    
    # Check for file operations
    if any(term in tool_name or term in tool_desc 
           for term in ['file', 'read', 'write', 'open', 'load']):
        probes.append(ProbeType.FILE_READ)
    
    # Check for command execution
    if any(term in tool_name or term in tool_desc 
           for term in ['exec', 'command', 'run', 'shell', 'terminal']):
        probes.append(ProbeType.COMMAND_EXEC)
    
    # Check for API endpoints
    if any(term in tool_name or term in tool_desc 
           for term in ['api', 'endpoint', 'http', 'https']):
        probes.append(ProbeType.API_ENDPOINT)
    
    # Check for authentication
    if any(term in tool_name or term in tool_desc 
           for term in ['auth', 'login', 'token', 'credential']):
        probes.append(ProbeType.AUTHENTICATION)
    
    return list(set(probes))  # Remove duplicates

async def execute_probes(tool: Dict[str, Any], mcp_client: Any, use_dynamic: bool = False) -> Dict[ProbeType, Dict[str, Any]]:
    """Execute all relevant probes for a tool."""
    results = {}
    probe_types = await get_relevant_probes(tool)
    
    for probe_type in probe_types:
        if probe_func := PROBE_REGISTRY.get(probe_type):
            try:
                result = await probe_func(mcp_client, tool, use_dynamic)
                results[probe_type.value] = result
            except Exception as e:
                logging.error(f"Error executing {probe_type} probe: {e}")
                results[probe_type.value] = {
                    "error": str(e),
                    "success": False
                }
    
    return results

@register_probe(ProbeType.FILE_READ)
async def probe_file_read(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for file read vulnerabilities."""
    result = ProbeResult(probe_type=ProbeType.FILE_READ, severity="high")
    result.attempts = []
    
    # Generate test files based on OS hints
    test_files = [
        "/etc/passwd", "/etc/hosts", "/etc/group",
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
    ]
    
    # Try different parameter names
    for test_file in test_files:
        for param in ['path', 'file', 'filename', 'filepath', 'input']:
            payload = {param: test_file}
            attempt = {"args": payload, "classification": "pending"}
            
            try:
                resp = await call_tool_with_client(mcp_client, tool['name'], payload)
                attempt["response"] = resp
                text = extract_result_text(resp) if resp else ""
                
                if looks_like_passwd(text):
                    attempt["classification"] = "vulnerable"
                    result.success = True
                    result.payload = payload
                    result.proof = f"Successfully read system file: {test_file}"
                    result.confidence = 0.9
                elif any(indicator in text for indicator in ['root:', '127.0.0.1', 'nobody:']):
                    attempt["classification"] = "suspicious"
                    result.success = True
                    result.payload = payload
                    result.proof = f"Suspicious file read detected: {text[:200]}..."
                    result.confidence = 0.7
                
                result.attempts.append(attempt)
                if result.success:
                    return result.to_dict()
                    
            except Exception as e:
                attempt["classification"] = "error"
                attempt["error"] = str(e)
                result.attempts.append(attempt)
    
    return result.to_dict()

@register_probe(ProbeType.COMMAND_EXEC)
async def probe_command_exec(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for command execution vulnerabilities."""
    result = ProbeResult(probe_type=ProbeType.COMMAND_EXEC, severity="critical")
    result.attempts = []
    
    test_commands = [
        {"command": "whoami"},
        {"cmd": "id"},
        {"exec": "echo test"},
        {"run": "hostname"}
    ]
    
    for cmd in test_commands:
        attempt = {"args": cmd, "classification": "pending"}
        try:
            resp = await call_tool_with_client(mcp_client, tool['name'], cmd)
            attempt["response"] = resp
            text = extract_result_text(resp) if resp else ""
            
            # Check for command output patterns
            if any(pattern in text.lower() for pattern in ["uid=", "windows", "linux", "unix"]):
                attempt["classification"] = "vulnerable"
                result.success = True
                result.payload = cmd
                result.proof = f"Command execution successful. Output: {text[:200]}..."
                result.confidence = 0.9
            
            result.attempts.append(attempt)
            if result.success:
                return result.to_dict()
                
        except Exception as e:
            attempt["classification"] = "error"
            attempt["error"] = str(e)
            result.attempts.append(attempt)
    
    return result.to_dict()

def looks_like_passwd(text: str) -> bool:
    return bool(re.search(r"^root:.*:0:0:", text, flags=re.MULTILINE))

def extract_result_text(resp: dict) -> str:
    if resp is None:
        return ""
    try:
        if "result" in resp and isinstance(resp["result"], dict):
            r = resp["result"]
            if "content" in r:
                c = r["content"]
                if isinstance(c, str):
                    return c
                if isinstance(c, list):
                    parts = []
                    for item in c:
                        if isinstance(item, dict):
                            t = item.get("text") or item.get("content") or ""
                            if isinstance(t, str):
                                parts.append(t)
                        elif isinstance(item, str):
                            parts.append(item)
                    return "\n".join(parts)
            for k in ("text", "value", "output"):
                if k in r and isinstance(r[k], str):
                    return r[k]
        return json.dumps(resp)
    except Exception:
        return json.dumps(resp)

async def probe_file_read(mcp_client, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """
    Test a tool for file read vulnerabilities.
    
    Args:
        mcp_client: MCP client instance for making tool calls
        tool: Tool definition dictionary
        use_dynamic: Whether to use dynamic LLM-based payload generation
        
    Returns:
        Dictionary with probe results
    """
    probe = {"success": False, "payload": None, "proof": None, "response": None, "attempts": []}

    # Generate payloads from LLM with the MCP client
    payloads_result = await generate_payloads(
        tool["name"],
        tool.get("description", ""),
        tool.get("raw", {}).get("inputSchema", {}),
        mcp_client=mcp_client,
        use_llm=use_dynamic
    )
    
    # Extract just the payloads from the results
    payloads = [p.get("payload") for p in payloads_result if p.get("payload")]

    if not payloads:
        return probe

    for payload in payloads:
        try:
            resp = await call_tool_with_client(mcp_client, tool["name"], payload)
            if resp is None:
                continue
        except Exception as e:
            logging.error("Error calling tool %s: %s", tool["name"], e)
            continue

        attempt = {"args": payload, "resp_short": str(resp)[:200] if resp else None}

        if not resp:
            attempt["classification"] = "no_response"
            probe["attempts"].append(attempt)
            continue

        text = extract_result_text(resp)

        if looks_like_passwd(text) or ("127.0.0.1" in text and "hosts" in text):
            attempt["classification"] = "vulnerable"
            probe.update(success=True, payload=payload, proof=text[:2000], response=resp)
            probe["attempts"].append(attempt)
            logging.info("FILE READ PROOF: %s", probe["proof"][:120])
            return probe
        elif "denied" in text.lower():
            attempt["classification"] = "denied"
        elif "invalid" in text.lower() or "error" in text.lower():
            attempt["classification"] = "invalid"
        else:
            attempt["classification"] = "success"

        probe["attempts"].append(attempt)

    return probe


def is_suspicious_behavior(tool_name: str, tool_desc: str, input_payload: Any, output_text: str) -> bool:
    """
    Detect if a tool is showing behavior that doesn't match its stated purpose.
    Returns True if the behavior is suspicious/indicative of tool poisoning.
    Uses contextual analysis to detect anomalies in tool behavior.
    """
    if not output_text or not isinstance(output_text, str):
        return False
    
    output_lower = output_text.lower()
    output_stripped = output_text.strip()
    
    # First, check for obviously safe outputs
    if not output_stripped:  # Empty output is not suspicious
        return False
    
    # Get tool purpose for better classification
    tool_purpose = f"{tool_name} {tool_desc}".lower()
    
    # Only define categories for tools that might be present on the server
    # This helps with categorizing the actual tools, not for testing non-existent ones
    tool_categories = {
        'sse_tool': ['sse_tool'],
        'file': ['file/read', 'file_read', 'read_file'],
        'system': ['system/exec', 'exec', 'execute', 'command']
    }
    
    # Determine tool category
    tool_category = None
    for category, keywords in tool_categories.items():
        if any(keyword in tool_purpose for keyword in keywords):
            tool_category = category
            break
    
    # Define expected output patterns for each category
    expected_patterns = {
        'greeting': [
            r'^[\w\s\-!,\.?]+$',  # Basic text with common punctuation
            r'^\s*Hello,\s*[^\n]*!?\s*$',
            r'^\s*Hi\b[^\n]*$',
            r'^\s*Welcome\b[^\n]*$',
            r'^\s*Greetings?\b[^\n]*$'
        ],
        'calculator': [
            r'^[\d\s\+\-\*/\.=()]+$',  # Basic math expressions
            r'^\s*[0-9]+(?:\.[0-9]+)?\s*$',  # Simple number
            r'^\s*[0-9]+(?:\.[0-9]+)?\s*[+\-*/]\s*[0-9]+(?:\.[0-9]+)?\s*=\s*[0-9]+(?:\.[0-9]+)?\s*$',
            r'^\s*[-+]?\d*\.?\d+\s*$'  # Any number
        ],
        'time': [
            r'^\s*\d{1,2}:\d{2}(?::\d{2})?\s*(?:[AP]M)?\s*$',  # Time format
            r'^\s*\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\s*$',
            r'^\s*(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s+[A-Za-z]+\s+\d{1,2},\s+\d{4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[AP]M)?)?\s*$',
            r'^\s*\d{1,2}/\d{1,2}/\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[AP]M)?)?\s*$',
            r'^[\d\s\-:APMapm/,]+$'  # General time/date characters
        ],
        'echo': [
            r'^.{0,500}$'  # Simple text response up to 500 chars
        ]
    }
    
    # If we know the tool's category, check if output matches expected patterns
    if tool_category and tool_category in expected_patterns:
        if any(re.match(p, output_text, re.IGNORECASE) for p in expected_patterns[tool_category]):
            return False  # Output matches expected patterns for this tool type
    
    # Check for clear indicators of command execution in output
    command_execution_indicators = [
        # System information patterns
        r'\b(?:uid|gid|groups?)=\d+',
        r'\b(?:user|username|hostname)\s*[:=]\s*[^\s\n]+',
        r'\b(?:home|pwd|path)\s*[:=]\s*[^\s\n]+',
        
        # Common command output patterns
        r'\b(?:drwx[rwx-]+\s+\d+\s+\w+\s+\w+\s+\d+\s+[^\n]+)',  # ls -l output
        r'\b(?:total \d+|total \d+\s+\d+)',  # du/ls -l header
        r'\b(?:Filesystem|Size|Used|Avail|Use%|Mounted on)\b',  # df output
        r'\b(?:Active|Connections|Proto|Recv-Q|Send-Q|Local Address|Foreign Address|State)\b',  # netstat/ss output
        
        # Shell prompt patterns
        r'\[?\w+@[\w-]+\s[^\s]+\]?[\$#]\s*$',
        
        # Command output headers
        r'^\s*(?:PID\s+USER|USER\s+PID|COMMAND\s+PID|MEM\s+USAGE)',
    ]
    
    # Check for actual command execution evidence
    has_command_output = any(
        re.search(p, output_text, re.IGNORECASE) 
        for p in command_execution_indicators
    )
    
    # Check for suspicious input patterns
    suspicious_input = False
    if input_payload:
        input_str = str(input_payload).lower()
        suspicious_input = any(
            re.search(p, input_str, re.IGNORECASE) 
            for p in command_execution_indicators
        )
    
    # If we have both suspicious input and command output, it's definitely suspicious
    if suspicious_input and has_command_output:
        return True
    
    # Check for specific security-sensitive patterns in output
    security_patterns = [
        # System files and sensitive data
        r'\b(?:passwd|shadow|group)\s*:',  # /etc/passwd or /etc/group format
        r'\b(?:ssh|rsa|dsa|ecdsa|ed25519)[-\s]*(?:key|id)[^\n]*-----',  # Private keys
        r'\b(?:AWS_ACCESS_KEY|AWS_SECRET_KEY|API[_-]?KEY|SECRET[_-]?KEY|PASSWORD|TOKEN)\s*[:=]\s*[^\s\n]+',
        
        # Dangerous commands
        r'\b(?:rm\s+-[rf]|del\s+/[sq]|format\s+[^\s]+|shutdown\s+\-h|killall|pkill|taskkill)',
        r'\b(?:/etc/(?:passwd|shadow|group|hosts?)|C:\\Windows\\System32)\\',
        
        # Code execution patterns
        r'\b(?:eval\(|exec\(|os\.system\()',
        r'\b(?:subprocess\.run\(|subprocess\.Popen\()',
        r'\b(?:import\s+os\s*$|import\s+subprocess\s*$|import\s+sys\s*$)',
        r'\b(?:__import__\(|getattr\(|setattr\()',
        r'\b(?:open\([^)]*,[^)]*w[^)]*\))',  # File write operations
        
        # Suspicious patterns
        r'\b(?:<|>|\|)',  # Redirection/pipe characters
        r'\b(?:&&|\|\||;|`|\$\()',  # Command chaining/substitution
        r'\b(?:echo|print)\s+[^\n]*\$\{',  # Variable expansion
    ]
    
    if any(re.search(pattern, output_text, re.IGNORECASE) for pattern in security_patterns):
        return True
        
    # Contextual analysis based on tool type
    if tool_category == 'greeting':
        # For greeting tools, be very strict about allowed output
        if len(output_stripped) > 100:  # Unusually long greeting
            return True
            
        # Check for suspicious characters that shouldn't be in a greeting
        if any(c in output_text for c in '{}[]|;`$()'):
            return True
            
        # Check for code execution patterns
        if re.search(r'\b(?:echo|print|exec|system|os\.|subprocess\.|import\s+os|import\s+subprocess)\b', output_text):
            return True
            
    elif tool_category == 'calculator':
        # For calculator tools, first check if it's an error response
        try:
            # Check if the output is a JSON error response
            error_data = json.loads(output_text)
            if 'error' in error_data:
                # If it's a validation error about invalid input type, it's expected behavior
                error_msg = json.dumps(error_data['error']).lower()
                if 'invalid_type' in error_msg and 'expected number' in error_msg:
                    return False
        except (json.JSONDecodeError, TypeError):
            # Not a JSON error, continue with normal validation
            pass
            
        # For successful calculations, only allow basic math expressions and results
        if not re.match(r'^[\d\s\+\-\*/\.,=()]+$', output_stripped):
            # If it's not a simple math expression, check if it's a common error message
            if not any(msg in output_lower for msg in ['error', 'invalid', 'expected']):
                return True
            
    elif tool_category == 'time':
        # For time/date tools, only allow time/date related formats
        if not re.match(r'^[\d\s\-:APMapm/,]+$', output_stripped):
            return True
            
    elif tool_category == 'echo':
        # For echo tools, limit the length and check for suspicious patterns
        if len(output_stripped) > 1000:  # Very long echo response
            return True
            
        if any(c in output_text for c in '{}[]|;`$()'):
            return True
    
    # For any tool, if we detected command output, it's suspicious
    return has_command_output


async def probe_exec(server: str, tool: Dict[str, Any], mcp_client, use_dynamic: bool = False) -> Dict[str, Any]:
    """
    Execute a tool with various payloads to test for command injection and tool poisoning.
    
    Args:
        server: Server name
        tool: Tool definition dictionary
        mcp_client: MCP client instance for making tool calls
        use_dynamic: Whether to use dynamic LLM-based payload generation
        
    Returns:
        Dictionary with probe results
    """
    tool_name = tool.get('name', '')
    tool_desc = tool.get('description', '')
    
    probe = {
        "success": False, 
        "payload": None, 
        "proof": None, 
        "response": None, 
        "attempts": [],
        "is_tool_poisoning": False
    }
    
    # Get tool metadata for better analysis
    tool_name = tool.get("name", "")
    tool_desc = tool.get("description", "")
    
    # Generate payloads from LLM with the MCP client
    payloads_result = await generate_payloads(
        tool_name,
        tool_desc,
        tool.get("raw", {}).get("inputSchema", {}),
        mcp_client=mcp_client,
        use_llm=use_dynamic
    )
    
    if not payloads_result:
        return probe
        
    # Check if the tool is designed to execute commands
    is_command_tool = any(term in tool_name.lower() or term in tool_desc.lower()
                        for term in ['command', 'exec', 'shell', 'terminal', 'sh', 'bash', 'cmd', 'powershell', 'run'])
    
    # Add bash command execution tests for non-command tools
    is_number_tool = (not is_command_tool and 
                     any(term in tool_name.lower() or term in tool_desc.lower()
                         for term in ['add', 'sum', 'plus', 'calculator', 'number']))
    
    if is_number_tool and not is_command_tool:
        # Check if the tool expects a 'command' parameter or 'a' and 'b' parameters
        input_schema = tool.get("raw", {}).get("inputSchema", {})
        properties = input_schema.get("properties", {})
        
        if "command" in properties:
            # Tool expects a 'command' parameter
            bash_tests = [
                ({"command": "`id`"}, "Command substitution with backticks"),
                ({"command": "$(id)"}, "Command substitution with $()"),
                ({"command": "; echo vulnerable;"}, "Command chaining"),
                ({"command": "; id"}, "Command injection with semicolon"),
                ({"command": "1 || id"}, "OR operator command injection"),
                ({"command": "1 && id"}, "AND operator command injection"),
                ({"command": "1 | id"}, "Pipe operator command injection"),
                ({"command": "1 > /tmp/test; id"}, "Redirection and command execution"),
                ({"command": "1; id;"}, "Multiple commands with semicolon"),
                ({"command": "1 || { id; }"}, "Command grouping"),
                ({"command": "1 || $(id)"}, "OR with command substitution")
            ]
        else:
            # Tool expects 'a' and 'b' parameters (legacy format)
            bash_tests = [
                ({"a": "`id`", "b": 1}, "Command substitution with backticks"),
                ({"a": "$(id)", "b": 1}, "Command substitution with $()"),
                ({"a": "; echo vulnerable;", "b": 1}, "Command chaining"),
                ({"a": "; id", "b": 1}, "Command injection with semicolon"),
                ({"a": "1 || id", "b": 1}, "OR operator command injection"),
                ({"a": "1 && id", "b": 1}, "AND operator command injection"),
                ({"a": "1 | id", "b": 1}, "Pipe operator command injection"),
                ({"a": "1 > /tmp/test; id", "b": 1}, "Redirection and command execution"),
                ({"a": "1; id;", "b": 1}, "Multiple commands with semicolon"),
                ({"a": "1 || { id; }", "b": 1}, "Command grouping"),
                ({"a": "1 || $(id)", "b": 1}, "OR with command substitution")
            ]
        
        # Add bash tests to the beginning of the payloads
        for payload, _ in bash_tests:
            if not any(p.get("payload") == payload for p in payloads_result):
                payloads_result.insert(0, {"payload": payload, "is_bash_test": True})
    
    # Track suspicious behaviors across all attempts
    suspicious_behaviors = []
    
    for result in payloads_result:
        if "payload" not in result:
            continue
            
        payload = result["payload"]
        attempt = {"args": payload, "resp_short": None, "classification": "pending"}
        
        try:
            # Use call_tool_with_client which handles different calling patterns
            resp = await call_tool_with_client(mcp_client, tool_name, payload)
            if resp is None:
                attempt["classification"] = "no_response"
                probe["attempts"].append(attempt)
                continue
            
            if not resp:
                attempt["classification"] = "no_response"
                probe["attempts"].append(attempt)
                continue
                
            text = extract_result_text(resp)
            attempt["resp_short"] = str(text)[:200] if text else None
            
            # Check for suspicious behavior
            if text:
                is_suspicious = is_suspicious_behavior(tool_name, tool_desc, payload, text)
                if is_suspicious:
                    suspicious_behaviors.append({
                        "payload": payload,
                        "response": text,  # Keep first 500 chars for evidence
                        "reason": "Tool behavior inconsistent with stated purpose"
                    })
            
            # Classify based on response
            if not text:
                attempt["classification"] = "no_output"
            elif "denied" in text.lower():
                attempt["classification"] = "denied"
            elif "invalid" in text.lower() or "error" in text.lower():
                attempt["classification"] = "error_response"
            else:
                attempt["classification"] = "success"
                
                # Only mark as success if we haven't detected suspicious behavior
                if not suspicious_behaviors:
                    # Create a properly structured proof object
                    proof_data = {
                        "tool_name": tool_name,
                        "tool_description": tool_desc,
                        "server": server,
                        "payload": payload,
                        "response": text.strip(),
                        "classification": "normal_behavior"
                    }
                    
                    probe.update(
                        success=True, 
                        payload=payload, 
                        proof=json.dumps(proof_data, indent=2, ensure_ascii=False),
                        response=resp
                    )
            
        except Exception as e:
            logging.error("Error in probe_exec for tool %s: %s", tool_name, str(e))
            attempt = {
                "args": payload, 
                "resp_short": str(e)[:200], 
                "classification": "error",
                "error": str(e)
            }
            
        probe["attempts"].append(attempt)
    
    # If we found suspicious behaviors, mark as tool poisoning
    if suspicious_behaviors:
        # Ensure we have valid JSON for the proof
        proof_data = {
            "suspicious_behaviors": suspicious_behaviors,
            "tool_name": tool["name"],
            "tool_description": tool.get("description", ""),
            "server": server
        }
        
        try:
            proof_json = json.dumps(proof_data, indent=2, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            logging.error(f"Failed to serialize proof data: {e}")
            # Fall back to a minimal valid JSON structure if serialization fails
            proof_json = json.dumps({
                "error": "Failed to serialize proof data",
                "tool_name": tool["name"],
                "server": server
            })
            
        probe.update(
            success=True,
            is_tool_poisoning=bool(suspicious_behaviors),  # Only mark as poisoning if we have behaviors
            proof=proof_json,
            payload=suspicious_behaviors[0]["payload"] if suspicious_behaviors else None
        )
        logging.warning("Potential tool poisoning detected in %s: %s", 
                      tool_name, suspicious_behaviors[0]["reason"])
    
    return probe

