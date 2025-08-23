# mcp_analyzer/llm_fuzzer.py

import asyncio
import json
import logging
import subprocess
from typing import Dict, List, Optional, Any, Union

from .tools import call_tool_with_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def generate_payloads(
    tool_name: str, 
    tool_description: str, 
    input_schema: Optional[Dict] = None, 
    mcp_client = None,
    use_llm: bool = True
) -> List[Dict[str, Any]]:
    """
    Generate test payloads for a given tool using LLM or predefined payloads.
    
    Args:
        tool_name: Name of the tool
        tool_description: Description of the tool
        input_schema: Input schema of the tool (if available)
        mcp_client: Optional MCP client for testing payloads and getting schema
        use_llm: Whether to use LLM for payload generation (default: True)
        
    Returns:
        List of generated payloads with metadata
    """
    # Special case for number addition tools (always use predefined payloads for these)
    if any(term in tool_name.lower() for term in ['add', 'sum', 'plus', 'calculator']) or \
       any(term in tool_description.lower() for term in ['add', 'sum', 'plus', 'calculate', 'number']):
        return [
            {"payload": {"a": 5, "b": 3}, "type": "basic", "description": "Basic addition"},
            {"payload": {"a": 4294967295, "b": 1}, "type": "large_numbers", "description": "Large number addition"},
            {"payload": {"a": -5, "b": 3}, "type": "negative_numbers", "description": "Negative number addition"},
            {"payload": {"a": 3.14, "b": 1.59}, "type": "decimal_numbers", "description": "Floating point addition"},
            {"payload": {"a": "5", "b": "3"}, "type": "string_numbers", "description": "String number addition"},
            {"payload": {"a": "", "b": 5}, "type": "edge_case", "description": "Empty string input"},
            {"payload": {"a": "5; id; echo ", "b": "3"}, "type": "security", "description": "Command injection attempt"},
            {"payload": {"a": "$(id)", "b": 1}, "type": "security", "description": "Command substitution attempt"},
            {"payload": {"a": "../../etc/passwd", "b": 0}, "type": "security", "description": "Path traversal attempt"},
            {"payload": {"a": "5' || id #", "b": 0}, "type": "security", "description": "SQL injection attempt"},
            {"payload": {"a": "1; DROP TABLE users --", "b": 0}, "type": "security", "description": "SQL injection attempt 2"}
        ]
    
    # If we have a client, try to get the tool's schema if not provided
    if mcp_client and hasattr(mcp_client, 'get_tool_schema') and not input_schema:
        try:
            schema = await mcp_client.get_tool_schema(tool_name)
            if schema and 'inputSchema' in schema:
                input_schema = schema['inputSchema']
                logger.debug(f"Retrieved schema for {tool_name}")
        except Exception as e:
            logger.warning(f"Could not get schema for {tool_name}: {e}")
    
    # If we have an input schema, use it to generate more targeted payloads
    schema_str = ""
    if input_schema:
        try:
            schema_str = json.dumps(input_schema, indent=2)
        except Exception as e:
            logger.error(f"Error serializing input schema: {e}")
    
    # If we have a client and want to use LLM for payload generation
    if use_llm and mcp_client and hasattr(mcp_client, 'call_tool'):
        try:
            # Construct the prompt for the LLM
            prompt = (
                "You are a security testing assistant. Generate test payloads for an API tool.\n"
                f"Tool name: {tool_name}\n"
                f"Description: {tool_description}\n"
            )
            
            if schema_str:
                prompt += (
                    f"Input schema (JSON Schema):\n{schema_str}\n\n"
                    "Generate exactly 3 JSON payloads as a JSON array of objects. "
                    "Each payload should be a valid input for this tool.\n"
                    "1. First payload: A normal, valid input that follows the schema exactly.\n"
                    "2. Second payload: A malicious input that attempts to exploit potential vulnerabilities.\n"
                    "3. Third payload: An edge-case input that tests the boundaries of the input validation.\n\n"
                    "⚠️ IMPORTANT: Only use fields defined in the schema. Do not invent new fields.\n"
                    "Return ONLY a valid JSON array of objects, with no other text or explanation."
                )
            else:
                prompt += (
                    "No input schema available. Generate 3 test payloads based on the tool name and description.\n"
                    "1. First payload: A normal, valid input.\n"
                    "2. Second payload: A malicious input that attempts to exploit potential vulnerabilities.\n"
                    "3. Third payload: An edge-case input that tests input validation.\n\n"
                    "Return ONLY a valid JSON array of objects, with no other text or explanation."
                )

            # Call the LLM with timeout
            logger.debug(f"Generating payloads for {tool_name} using LLM...")
            try:
                result = await asyncio.wait_for(
                    _call_llm(prompt),
                    timeout=60  # 60 second timeout
                )
                
                # Process the output
                output = result.strip()
                
                # Extract JSON from markdown code blocks if present
                if output.startswith("```"):
                    parts = output.split("```")
                    output = parts[1].strip() if len(parts) > 1 else output
                    if output.startswith("json\n"):
                        output = output[5:]
                
                # Find the JSON array in the output
                start = output.find('[')
                end = output.rfind(']')
                
                if start == -1 or end == -1:
                    raise ValueError("Could not find JSON array in LLM output")
                    
                json_str = output[start:end+1]
                payloads = json.loads(json_str)
                
                if not isinstance(payloads, list):
                    payloads = [payloads]
                    
                # Add metadata to each payload
                result = []
                for i, payload in enumerate(payloads, 1):
                    if not isinstance(payload, dict):
                        logger.warning(f"Skipping invalid payload (not a dict): {payload}")
                        continue
                        
                    result.append({
                        "payload": payload,
                        "type": "llm_generated",
                        "description": f"Generated by LLM (variant {i})",
                        "source": "llm"
                    })
                
                logger.info(f"Generated {len(result)} payloads for {tool_name} using LLM")
                return result
                
            except asyncio.TimeoutError:
                logger.error("LLM generation timed out")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse LLM output as JSON: {e}")
                logger.debug(f"LLM output: {output}")
            except Exception as e:
                logger.error(f"Error during LLM payload generation: {e}", exc_info=True)
                
        except Exception as e:
            logger.error(f"Unexpected error during LLM payload generation: {e}", exc_info=True)
    
    # Fallback to basic payloads if LLM generation fails or is disabled
    logger.info(f"Using fallback payloads for {tool_name}")
    return [
        {"payload": {}, "type": "empty", "description": "Empty payload", "source": "fallback"},
        {"payload": {"input": "test"}, "type": "basic", "description": "Basic test input", "source": "fallback"},
        {"payload": {"query": "SELECT * FROM users"}, "type": "security", "description": "SQL query test", "source": "fallback"}
    ]


async def _call_llm(prompt: str) -> str:
    """Helper function to call the LLM with the given prompt.
    
    Args:
        prompt: The prompt to send to the LLM
        
    Returns:
        The raw text output from the LLM
    """
    # Use subprocess to call the LLM (e.g., Ollama)
    process = await asyncio.create_subprocess_exec(
        "ollama", "run", "mistral",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    try:
        # Send the prompt and wait for completion
        stdout, stderr = await process.communicate(input=prompt.encode())
        
        if process.returncode != 0:
            error_msg = stderr.decode().strip()
            raise RuntimeError(f"LLM error (code {process.returncode}): {error_msg}")
            
        return stdout.decode().strip()
        
    except Exception as e:
        logger.error(f"Error calling LLM: {e}")
        raise


