# mcp_analyzer/llm_fuzzer.py

import subprocess, json, logging
from typing import Dict, List

async def generate_payloads(tool_name: str, tool_description: str, input_schema: Dict = None, mcp_client = None) -> List[Dict]:
    """
    Generate test payloads for a given tool using LLM.
    
    Args:
        tool_name: Name of the tool
        tool_description: Description of the tool
        input_schema: Input schema of the tool (if available)
        mcp_client: Optional MCP client for testing payloads
        
    Returns:
        List of generated payloads
    """
    # Special case for number addition tools
    if any(term in tool_name.lower() for term in ['add', 'sum', 'plus', 'calculator']) or \
       any(term in tool_description.lower() for term in ['add', 'sum', 'plus', 'calculate', 'number']):
        return [
            # Basic number addition
            {"a": 5, "b": 3},
            # Large numbers
            {"a": 4294967295, "b": 1},
            # Negative numbers
            {"a": -5, "b": 3},
            # Decimal numbers
            {"a": 3.14, "b": 1.59},
            # String numbers
            {"a": "5", "b": "3"},
            # Empty string
            {"a": "", "b": 5},
            # Command injection attempts
            {"a": "5; id; echo ", "b": "3"},
            {"a": "$(id)", "b": 1},
            # Path traversal
            {"a": "../../etc/passwd", "b": 0},
            # Special characters
            {"a": "5' || id #", "b": 0},
            # SQL injection
            {"a": "1; DROP TABLE users --", "b": 0}
        ]
        
    print(f"[LLM-FUZZER] Preparing to call Ollama for tool: {tool_name}")
    try:
        schema_str = json.dumps(input_schema, indent=2) if input_schema else ""
    except Exception:
        schema_str = ""
    # Construct the prompt for Mistral
    prompt = (
            f"Tool name: {tool_name}\n"
            f"Description: {tool_description}\n"
            f"Input schema (JSON Schema): {schema_str}\n"
            "Generate exactly 3 JSON payloads as a JSON array of objects.\n"
            "- First: a valid payload.\n"
            "- Second: a malicious payload attempting to exploit vulnerabilities (e.g., path traversal like '../../etc/passwd', accessing OS files like '/etc/shadow', '/etc/hosts', or other sensitive files).\n"
            "- Third: an edge-case payload (e.g., empty string, very large numbers, unusual characters).\n"
            "⚠️ Only use the fields defined in the schema. Do not invent new keys.\n"
            "Return only the JSON array, no explanation."
    )
    try:
        print(f"[LLM-FUZZER] Running ollama call...")
        result = subprocess.run(
            ["ollama", "run", "mistral"],
            input=prompt, text=True, capture_output=True, timeout=60
        )
        print("[LLM-FUZZER] Ollama call finished.")
    except Exception as e:
        logging.error(f"LLM invocation failed for {name}: {e}")
        print("[LLM-FUZZER] ERROR: Ollama call failed")
        print(e.stderr.decode("utf-8"))
        return []
    if result.returncode != 0:
        logging.error(f"Mistral error (code {result.returncode}): {result.stderr.strip()}")
        return []
    output = result.stdout.strip()

    # Remove Markdown fences if any, then extract JSON array
    if output.startswith("```"):
        parts = output.split("```")
        output = parts[-1].strip() if len(parts) > 1 else output
    start = output.find('['); end = output.rfind(']')
    json_str = output[start:end+1] if (start!=-1 and end!=-1) else output
    try:
        payloads = json.loads(json_str)

        # normalize to list
        if isinstance(payloads, dict):
            payloads = [payloads]
        if not isinstance(payloads, list):
            logging.error(f"Unexpected LLM output format: {payloads}")
            return []

        results = []
        for i, p in enumerate(payloads, 1):
            logging.info(f"[LLM-FUZZER] Payload {i} for tool {tool_name}: {json.dumps(p, indent=2)}")
            print(f"[LLM-FUZZER] Payload {i} for tool {tool_name}: {json.dumps(p, indent=2)}")

            if mcp_client is not None:
                try:
                    # call the tool asynchronously
                    response = await mcp_client.call_tool(tool_name, p)
                    logging.info(f"[LLM-FUZZER] Response {i} from {tool_name}: {response}")
                    print(f"[LLM-FUZZER] Response {i} from {tool_name}: {response}\n")
                    results.append({"payload": p, "response": response})
                except Exception as e:
                    logging.error(f"Error running payload {i} on {tool_name}: {e}")
                    print(f"[LLM-FUZZER] ERROR calling tool {tool_name} with payload {i}: {e}\n")
                    results.append({"payload": p, "error": str(e)})
            else:
                # Just return the generated payload without calling the tool
                results.append({"payload": p})

        return results

    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON from LLM output: {e}\n{json_str}")
        return []


