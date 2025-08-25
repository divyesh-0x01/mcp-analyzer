# mcp_analyzer/llm_fuzzer.py

import asyncio
import json
import logging
import subprocess
from typing import Dict, List, Optional, Any, Union

from .tools import call_tool_with_client
from .enhanced_payload_generator import HybridPayloadGenerator, PayloadResult
from .static_payload_generator import StaticPayloadGenerator, StaticPayloadResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def generate_payloads(
    tool_name: str, 
    tool_description: str, 
    input_schema: Optional[Dict] = None, 
    mcp_client = None,
    use_llm: bool = True,
    use_static: bool = False
) -> List[Dict[str, Any]]:
    """
    Generate test payloads for a given tool using enhanced hybrid approach or static approach.
    
    Args:
        tool_name: Name of the tool
        tool_description: Description of the tool
        input_schema: Input schema of the tool (if available)
        mcp_client: Optional MCP client for testing payloads and getting schema
        use_llm: Whether to use LLM for payload generation (default: True)
        use_static: Whether to use static payload generation (default: False)
        
    Returns:
        List of generated payloads with metadata
    """
    
    # If we have a client, try to get the tool's schema if not provided
    if mcp_client and hasattr(mcp_client, 'get_tool_schema') and not input_schema:
        try:
            schema = await mcp_client.get_tool_schema(tool_name)
            if schema and 'inputSchema' in schema:
                input_schema = schema['inputSchema']
                logger.debug(f"Retrieved schema for {tool_name}")
        except Exception as e:
            logger.warning(f"Could not get schema for {tool_name}: {e}")

    # Special case for number addition tools (use predefined payloads only if not using LLM)
    is_calculator_tool = any(term in tool_name.lower() for term in ['add', 'sum', 'plus', 'calculator']) or \
       any(term in tool_description.lower() for term in ['add', 'sum', 'plus', 'calculate', 'number'])

    # Only use calculator payloads if schema matches expected (properties include 'a' and 'b')
    schema_has_a_b = False
    if isinstance(input_schema, dict) and 'properties' in input_schema:
        props = set(input_schema.get('properties', {}).keys())
        schema_has_a_b = {'a', 'b'}.issubset(props)

    if is_calculator_tool and not use_llm and schema_has_a_b:
        return [
            {"payload": {"a": 5, "b": 3}, "type": "basic", "description": "Basic addition"},
            {"payload": {"a": 4294967295, "b": 1}, "type": "large_numbers", "description": "Large number addition"},
            {"payload": {"a": -5, "b": 3}, "type": "negative_numbers", "description": "Negative number addition"},
            {"payload": {"a": 3.14, "b": 1.59}, "type": "decimal_numbers", "description": "Floating point addition"},
            {"payload": {"a": "5", "b": "3"}, "type": "string_numbers", "description": "String number addition"},
            {"payload": {"a": "", "b": 5}, "type": "edge_case", "description": "Empty string input"},
            {"payload": {"a": "5; id; echo ", "b": 3}, "type": "security", "description": "Command injection attempt"},
            {"payload": {"a": "$(id)", "b": 1}, "type": "security", "description": "Command substitution attempt"},
            {"payload": {"a": "../../etc/passwd", "b": 0}, "type": "security", "description": "Path traversal attempt"},
            {"payload": {"a": "5' || id #", "b": 0}, "type": "security", "description": "SQL injection attempt"},
            {"payload": {"a": "1; DROP TABLE users --", "b": 0}, "type": "security", "description": "SQL injection attempt 2"}
        ]
    
    # Use static payload generator (fast, reliable, no external dependencies)
    if use_static:
        try:
            logger.info(f"Using static payload generator for {tool_name}")
            
            # Initialize the static generator
            static_generator = StaticPayloadGenerator()
            
            # Generate static payloads
            static_payload_results = static_generator.generate_payloads(
                tool_name, tool_description, input_schema or {}
            )
            
            # Convert StaticPayloadResult objects to the expected format
            result = []
            for payload_result in static_payload_results:
                result.append({
                    "payload": payload_result.payload,
                    "type": payload_result.attack_type,
                    "description": f"{payload_result.technique} - {payload_result.expected_behavior}",
                    "source": "static",
                    "risk_level": payload_result.risk_level,
                    "technique": payload_result.technique,
                    "expected_behavior": payload_result.expected_behavior,
                    "category": payload_result.category
                })
            
            logger.info(f"Generated {len(result)} static payloads for {tool_name}")
            return result
            
        except Exception as e:
            logger.error(f"Static payload generation failed: {e}", exc_info=True)
    
    # Use the new hybrid payload generator (dynamic approach)
    elif use_llm and mcp_client and hasattr(mcp_client, 'call_tool'):
        try:
            logger.info(f"Using enhanced hybrid payload generator for {tool_name}")
            
            # Initialize the hybrid generator
            generator = HybridPayloadGenerator()
            
            # Generate payloads using multiple approaches (LLM disabled by default)
            payload_results = await generator.generate_payloads(
                tool_name, tool_description, input_schema or {}, use_llm=False
            )
            
            # Convert PayloadResult objects to the expected format
            result = []
            for payload_result in payload_results:
                result.append({
                    "payload": payload_result.payload,
                    "type": payload_result.attack_type,
                    "description": f"{payload_result.technique} - {payload_result.expected_behavior}",
                    "source": payload_result.source,
                    "risk_level": payload_result.risk_level,
                    "technique": payload_result.technique,
                    "expected_behavior": payload_result.expected_behavior
                })
            
            logger.info(f"Generated {len(result)} enhanced payloads for {tool_name}")
            return result
            
        except Exception as e:
            logger.error(f"Enhanced payload generation failed: {e}", exc_info=True)
    
    # Fallback to basic payloads if enhanced generation fails or is disabled
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


