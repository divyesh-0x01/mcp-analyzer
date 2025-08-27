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
    
    # Check for command execution (but exclude HTTP/curl tools and bash-specific tools)
    if any(term in tool_name or term in tool_desc 
           for term in ['exec', 'command', 'run', 'shell', 'terminal']):
        # Don't add COMMAND_EXEC if it's clearly an HTTP/API tool
        if not any(http_term in tool_name or http_term in tool_desc 
                  for http_term in ['curl', 'http', 'https', 'api', 'endpoint', 'request']):
            # Don't add COMMAND_EXEC if it's a bash-specific tool (needs different payloads)
            if not any(bash_term in tool_name.lower() for bash_term in ['bash_pipe', 'bash_execute']):
                probes.append(ProbeType.COMMAND_EXEC)
    
    # Check for bash-specific tools (bash_pipe, bash_execute)
    if any(term in tool_name.lower() for term in ['bash_pipe', 'bash_execute']):
        probes.append(ProbeType.BASH_EXEC)
    
    # Check for API endpoints (prioritize this over command execution for HTTP tools)
    if any(term in tool_name or term in tool_desc 
           for term in ['api', 'endpoint', 'http', 'https', 'curl', 'request']):
        probes.append(ProbeType.API_ENDPOINT)
    
    # Check for authentication
    if any(term in tool_name or term in tool_desc 
           for term in ['auth', 'login', 'token', 'credential']):
        probes.append(ProbeType.AUTHENTICATION)
    
    # For dynamic fuzzing, always include a general probe for all tools
    # This will be handled in execute_probes function
    
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

    from .static_payload_generator import StaticPayloadGenerator
    generator = StaticPayloadGenerator()
    # Select only context/role/instruction manipulation payloads
    pi_payloads = [p for p in generator._load_static_payloads() if p.attack_type in {
        "context_manipulation", "role_confusion", "instruction_injection", "delimiter_attack", "encoding_attack"
    }]

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

            # If execution traces or sensitive outputs appear, mark as vulnerable
            if looks_like_passwd(text) or any(s in text for s in ["uid=", "root:", "/etc/passwd"]):
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

            if any(tok in text for tok in ["Method not found", "invalid", "denied", "error"]):
                attempt["classification"] = "error_response"
            else:
                attempt["classification"] = "success"
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


@register_probe(ProbeType.FILE_READ)
async def probe_file_read(mcp_client: Any, tool: Dict[str, Any], use_dynamic: bool = False) -> Dict[str, Any]:
    """Probe for file read vulnerabilities using tool schema for parameter names."""
    result = ProbeResult(probe_type=ProbeType.FILE_READ, severity="high")
    result.attempts = []

    # Comprehensive path traversal test cases
    test_files = [
        # Standard path traversal attempts
        "/tmp/../etc/passwd",
        "/tmp/../etc/hosts",
        "/tmp/safe/../../etc/passwd",  # New payload
        "/etc/passwd",                 # New payload - direct path
        "/etc/hosts",                  # New payload - direct path
        # Windows path traversal
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        # Additional variations
        "/var/tmp/../../../etc/passwd",
        "/usr/local/../../etc/passwd"
    ]

    # Get parameter info from tool schema
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
            # Get list of required parameters if specified
            required_params = schema.get('required', [])
            
            # If there are required params, use those first
            if required_params:
                param_names = required_params
            else:
                # Otherwise try to find parameters that look like they accept file paths
                for param, props in param_properties.items():
                    if isinstance(props, dict):
                        # Look for parameters with 'file' or 'path' in name or type
                        param_lower = param.lower()
                        if ('file' in param_lower or 'path' in param_lower or 
                            (isinstance(props.get('type'), str) and 
                             any(t in props['type'].lower() for t in ['string', 'file', 'path']))):
                            param_names.append(param)
                
                # If no file-like params found, use all parameters
                if not param_names and param_properties:
                    param_names = list(param_properties.keys())
    except Exception as e:
        logging.debug(f"Error getting tool schema for {tool.get('name', 'unknown')}: {e}")

    # Fallback to common parameter names if we couldn't determine them from the schema
    if not param_names:
        param_names = ['filename', 'file', 'path', 'filepath', 'input']
        logging.info(f"Using fallback parameter names for {tool.get('name', 'unknown')}")
    else:
        logging.info(f"Using parameters for {tool.get('name', 'unknown')}: {param_names}")
        if required_params:
            logging.info(f"Required parameters: {required_params}")
    
    # Remove any duplicate parameters while preserving order
    seen = set()
    param_names = [x for x in param_names if not (x in seen or seen.add(x))]

    for test_file in test_files:
        for param in param_names:
            # Create payload with all required parameters that have default values
            payload = {}
            
            # Add the current parameter with test file
            payload[param] = test_file
            
            # Add other required parameters with default values if they exist
            for req_param in required_params:
                if req_param != param and req_param not in payload:
                    # Try to get default from schema or use empty string
                    default_value = ""
                    if req_param in param_properties and isinstance(param_properties[req_param], dict):
                        prop = param_properties[req_param]
                        if 'default' in prop:
                            default_value = prop['default']
                        elif 'type' in prop:
                            # Provide type-appropriate default values
                            if prop['type'] == 'number':
                                default_value = 0
                            elif prop['type'] == 'boolean':
                                default_value = False
                            elif prop['type'] == 'array':
                                default_value = []
                            elif prop['type'] == 'object':
                                default_value = {}
                    payload[req_param] = default_value
            
            attempt = {"args": payload, "classification": "pending"}
            try:
                resp = await call_tool_with_client(mcp_client, tool['name'], payload)
                attempt["response"] = resp
                text = extract_result_text(resp) if resp else ""
                attempt["classification"] = "safe"

                # Check for successful file read
                if looks_like_passwd(text) or text.startswith("root:"):
                    attempt["classification"] = "vulnerable"
                    result.success = True
                    result.payload = payload
                    result.proof = json.dumps({
                        "payload": payload,
                        "response": extract_concise_response(text)
                    }, ensure_ascii=False)
                    result.confidence = 0.95
                    result.attempts.append(attempt)
                    logging.warning(f"File read vulnerability found in {tool.get('name', 'unknown')} with parameter '{param}'")
                    return result.to_dict()
                    
                # Check for hosts file read
                if "127.0.0.1" in text and "hosts" in text:
                    attempt["classification"] = "vulnerable"
                    result.success = True
                    result.payload = payload
                    result.proof = json.dumps({
                        "payload": payload,
                        "response": extract_concise_response(text)
                    }, ensure_ascii=False)
                    result.confidence = 0.85
                    result.attempts.append(attempt)
                    logging.warning(f"Hosts file read vulnerability found in {tool.get('name', 'unknown')} with parameter '{param}'")
                    return result.to_dict()
                    
            except Exception as e:
                error_msg = str(e).lower()
                if 'validation' in error_msg or 'field required' in error_msg:
                    attempt["classification"] = "invalid_parameter"
                    # Provide more detailed validation error information
                    if hasattr(e, 'response') and hasattr(e.response, 'text'):
                        try:
                            error_data = json.loads(e.response.text)
                            if 'detail' in error_data:
                                if isinstance(error_data['detail'], list):
                                    # Handle FastAPI-style validation errors
                                    error_msgs = [f"{err['loc'][-1]}: {err['msg']}" 
                                                for err in error_data['detail'] 
                                                if 'loc' in err and 'msg' in err]
                                    if error_msgs:
                                        error_msg = "; ".join(error_msgs)
                                else:
                                    error_msg = str(error_data['detail'])
                                    
                            attempt["error"] = error_msg
                            logging.debug(f"Validation error for {tool.get('name', 'unknown')} with payload {payload}: {error_msg}")
                        except (json.JSONDecodeError, AttributeError, KeyError):
                            attempt["error"] = str(e)
                    continue
                
                attempt["classification"] = "error"
                attempt["error"] = str(e)
                logging.warning(f"Error testing {tool.get('name', 'unknown')} with parameter '{param}': {e}", 
                             exc_info=logging.DEBUG >= logging.root.level)
            
            result.attempts.append(attempt)
    
    return result.to_dict()

    # Generate payloads from LLM with the MCP client
    payloads_result = await generate_payloads(
        tool_name=tool.get('name', ''),
        tool_description=tool.get('description', ''),
        input_schema=tool.get('inputSchema', {}),
        mcp_client=mcp_client,
        use_llm=use_dynamic
    )

    # Extract payloads from the results, including empty payloads for tools with no parameters
    payloads = []
    for p in payloads_result:
        payload = p.get("payload")
        if payload is not None:  # Include both empty {} and non-empty payloads
            payloads.append(payload)

    if not payloads:
        return probe

    # Add static file read payloads only for tools that accept file parameters
    if param_names:  # Only add if tool has parameters
        test_files = [
            "/tmp/../etc/passwd",  # Updated path traversal
            "/tmp/../etc/hosts",   # Updated path traversal
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        for param in param_names:
            for file in test_files:
                payload = {param: file}
                payloads.append(payload)

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
    
    # Generate payloads from LLM with the MCP client
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
            "suspicious_behavior_detected": True,
            "total_suspicious_behaviors_found": len(suspicious_behaviors),
            "representative_proof": {
                "payload": representative_behavior["payload"],
                "response": representative_behavior["response"],
                "reason": representative_behavior["reason"]
            },
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
    else:
        # No suspicious behaviors found - emit a minimal safe note and skip verbose proof
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

