from __future__ import annotations
import os, re, json, logging
from typing import Any, Dict
from .tools import call_tool_rpc
from .llm_fuzzer import generate_payloads
import logging
from .utils import extract_result_text, looks_like_passwd
from .constants import (
    COMMON_PATH_KEYS, COMMON_CMD_KEYS, COMMON_ARG_FOR_POSITIONAL,
    UNIX_SENSITIVE, WIN_SENSITIVE, BENIGN_CMD, BENIGN_CMD_ALT
)

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

async def probe_file_read(mcp_client, tool: Dict[str, Any]) -> Dict[str, Any]:
    probe = {"success": False, "payload": None, "proof": None, "response": None, "attempts": []}

    # Generate payloads from LLM
    payloads = await generate_payloads(
        tool["name"],
        tool.get("description", ""),
        tool.get("raw", {}).get("inputSchema", {})
    )

    if not payloads:
        return probe

    for payload in payloads:
        try:
            resp = await mcp_client.call_tool(tool["name"], payload)
        except Exception as e:
            resp = None
            logging.error("Error calling tool %s: %s", tool["name"], e)

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
    """
    if not output_text or not isinstance(output_text, str):
        return False
        
    tool_purpose = f"{tool_name} {tool_desc}".lower()
    output_lower = output_text.lower()
    
    # Common error messages that should not be considered suspicious
    error_indicators = [
        r'command not found',
        r'no such file or directory',
        r'permission denied',
        r'error:',
        r'failed',
        r'not found',
        r'invalid',
        r'failed to execute',
        r'syntax error',
        r'not recognized',
        r'no such command',
        r'unknown command',
    ]
    
    # Check if this looks like an error message
    if any(err in output_lower for err in error_indicators):
        return False
    
    # Check for actual command execution indicators
    command_indicators = [
        # System information
        r'\b(uid=\d+\()',
        r'\b(home|pwd|path)=[^\s\n]+',
        r'\b(hostname|uname|whoami|id)\s*=',
        # File system access with paths
        r'\b(ls|dir|cat|type|more|less|head|tail)\s+[^\s&|;`$(){}]*[./]',
        # Network commands with arguments
        r'\b(ifconfig|ipconfig|netstat|ping|nslookup|dig|traceroute|tracert|curl|wget|netcat|nc)\s+',
        # Process commands with arguments
        r'\b(ps|top|htop|tasklist|taskkill|kill|pkill|pgrep)\s+',
        # Shell metacharacters in context
        r'[;&|`$(){}]\s*\w',
        # Common sensitive file paths
        r'/etc/passwd', 
        r'/etc/shadow', 
        r'/etc/hosts', 
        r'C:\\Windows\\System32',
        # Environment variables in use
        r'\$(\w+|\{[^}]+\})',
    ]
    
    # Check for system information in output that shouldn't be there
    has_system_info = any(re.search(pattern, output_text) for pattern in command_indicators)
    
    # Check if tool behavior is inconsistent with its stated purpose
    is_inconsistent = False
    
    # Simple tools should never show system info
    simple_functions = ['greet', 'hello', 'calculator', 'calculate', 'convert', 'formatter']
    is_simple_tool = any(fn in tool_purpose for fn in simple_functions)
    
    if is_simple_tool and has_system_info:
        # Check if this is actually command output (not just mentioning commands in help text)
        has_actual_output = any(
            re.search(r'\b' + re.escape(cmd) + r'\b.*\n', output_text) 
            for cmd in ['user', 'hostname', 'pwd', 'ls', 'cat']
        )
        if has_actual_output:
            is_inconsistent = True
    
    # Check if this is a bash test we injected by looking at the payload
    is_bash_test = False
    if isinstance(input_payload, dict):
        # Check if any value in the payload contains command injection patterns
        is_bash_test = any(
            key in input_payload and 
            any(cmd in str(input_payload.get(key, '')).lower() 
                for cmd in ['id', 'echo', ';', '|', '&&', '||', '`', '$(', '>', '<', '>>', '&', 'exec', 'system'])
            for key in input_payload
        )
    
    # Check if the tool is designed to execute commands
    # Also check if the tool name or description indicates it's a command execution tool
    tool_name_lower = tool_name.lower() if tool_name else ''
    tool_purpose_lower = tool_purpose.lower()
    
    is_command_tool = any(term in tool_purpose_lower for term in 
                         ['command', 'exec', 'shell', 'terminal', 'sh', 'bash', 'cmd', 'powershell', 'run'])
    
    # Special case for add_numbers tool - it's not a command execution tool
    if 'add_numbers' in tool_name_lower or 'add numbers' in tool_purpose_lower:
        is_command_tool = False
        
        # Check if the output contains command execution results
        if has_system_info:
            # If we see command output (like uid, gid, etc.), it's a real security issue
            command_output_indicators = [
                r'uid=\d+',
                r'gid=\d+',
                r'groups=\d+',
                r'command not found',
                r'syntax error',
                r'error:',
                r'invalid',
                r'failed',
                r'not found'
            ]
            
            # If we see any of these in the output, it's a real security issue
            if any(re.search(pattern, output_text.lower()) for pattern in command_output_indicators):
                # But only if it's not just an error message
                if 'command not found' in output_text.lower() or 'syntax error' in output_text.lower():
                    return False
                return True
            
            # If the output is a simple number, it's expected behavior
            if re.match(r'^\s*\d+\s*$', output_text.strip()):
                return False
                
            # If the output is empty or just whitespace, don't flag it
            if not output_text.strip():
                return False
                
            # If we get here, it's not a simple number but also doesn't contain command output
            # So it's likely not a security issue
            return False
    
    # If we detect command execution in a non-command tool that wasn't from our test
    if has_system_info and not (is_command_tool or is_bash_test):
        # Look for command output patterns
        command_output_patterns = [
            r'\n\s*\w+@[\w-]+',  # username@hostname
            r'\b(uid|gid|groups?)=',  # id command output
            r'\b(cwd|pwd)\s*[:=]',  # Current working directory
            r'\b(user|hostname|pwd|ls|cat)\b.*\n',  # Common command names with output
            r'\n\s*\d+\s+\d+\s+\d+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+[^\n]+',  # ls -l output
        ]
        
        has_command_output = any(re.search(pattern, output_text) for pattern in command_output_patterns)
        
        if has_command_output:
            # Check if this is a false positive by looking for help text
            is_help_text = any(term in output_text.lower() for term in 
                             ['usage:', 'help:', 'options:', 'commands:', '--help'])
            
            if not is_help_text:
                is_inconsistent = True
    
    # Check for unexpected security-related patterns
    security_patterns = [
        r'\b(root|admin|sudo|privileged)\b',
        r'\b(TOOL POISONING DETECTED)\b',
        r'\b(secret|key|token|password|pwd|passwd|credential)\s*[:=]',
    ]
    
    has_security_issue = any(re.search(pattern, output_text, re.IGNORECASE) 
                           for pattern in security_patterns)
    
    # Only flag as suspicious if we're very confident
    return (has_system_info and is_inconsistent) or has_security_issue


async def probe_exec(server: str, tool: Dict[str, Any], reader, writer) -> Dict[str, Any]:
    """
    Execute a tool with various payloads to test for command injection and tool poisoning.
    
    Args:
        server: Server name
        tool: Tool definition dictionary
        reader: Async reader for RPC communication
        writer: Async writer for RPC communication
        
    Returns:
        Dictionary with probe results
    """
    probe = {
        "success": False, 
        "payload": None, 
        "proof": None, 
        "response": None, 
        "attempts": [],
        "is_tool_poisoning": False
    }
    
    class SimpleMCPClient:
        def __init__(self, reader, writer):
            self.reader = reader
            self.writer = writer
        
        async def call_tool(self, tool_name, payload):
            from .rpc import send_jsonrpc, recv_json_until, next_id
            request_id = next_id()
            await send_jsonrpc(self.writer, {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": tool_name,
                "params": payload
            })
            return await recv_json_until(self.reader, request_id, timeout=5.0)
    
    mcp_client = SimpleMCPClient(reader, writer)
    
    # Get tool metadata for better analysis
    tool_name = tool.get("name", "")
    tool_desc = tool.get("description", "")
    
    # Generate payloads from LLM with the MCP client
    payloads_result = await generate_payloads(
        tool_name,
        tool_desc,
        tool.get("raw", {}).get("inputSchema", {}),
        mcp_client=mcp_client
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
            # Try both call patterns to be compatible with different server implementations
            resp = None
            try:
                resp = await call_tool_rpc(reader, writer, tool_name, payload, timeout=5.0)
            except Exception as e:
                try:
                    resp = await mcp_client.call_tool(tool_name, payload)
                except Exception as inner_e:
                    logging.error("Error calling tool %s: %s", tool_name, str(inner_e))
                    attempt["classification"] = "error"
                    attempt["error"] = str(inner_e)
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
                    probe.update(
                        success=True, 
                        payload=payload, 
                        proof=text.strip(), 
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
        probe.update(
            success=True,
            is_tool_poisoning=True,
            proof=json.dumps({
                "suspicious_behaviors": suspicious_behaviors,
                "tool_name": tool["name"],
                "tool_description": tool.get("description", ""),
            }, indent=2, ensure_ascii=False),
            payload=suspicious_behaviors[0]["payload"]
        )
        logging.warning("Potential tool poisoning detected in %s: %s", 
                      tool_name, suspicious_behaviors[0]["reason"])
    
    return probe

