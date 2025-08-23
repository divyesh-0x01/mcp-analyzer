# mcp_analyzer/server.py
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shlex
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from rich.console import Console

from .auth import has_auth_env
from .rpc import send_jsonrpc, recv_json_until, next_id
from .constants import VERSION, LIST_METHODS
from .classify import static_classify
from .findings import Finding
from .probes import execute_probes, ProbeType

console = Console()
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Helpers: perform login/token exchange and inject Authorization header
# -------------------------------------------------------------------
async def _perform_login_and_inject_header(auth_cfg: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, str]:
    """
    If auth_cfg.method == 'login', POST to auth_cfg['url'] to fetch token.
    Supports:
      - use_form_data: true -> sends form-encoded (application/x-www-form-urlencoded)
      - otherwise sends JSON body
      - basic auth nested in auth_cfg.get('auth') with type == 'basic'
      - extracts token using token_path (list of keys)
      - injects header (auth_cfg['header'] or 'Authorization') with prefix (auth_cfg['prefix'] or '')
    Returns modified headers dict.
    Raises on missing token or non-200 response.
    """
    if not isinstance(auth_cfg, dict):
        return headers

    method = str(auth_cfg.get("method", "")).lower()
    if method != "login":
        return headers

    token_url = auth_cfg.get("url")
    if not token_url:
        raise RuntimeError("auth.method=login but no auth.url provided")

    use_form = bool(auth_cfg.get("use_form_data", False))
    creds = auth_cfg.get("credentials", {}) or {}
    nested_auth = auth_cfg.get("auth") or {}  # e.g., basic auth config

    # Prepare aiohttp auth if basic
    aio_auth = None
    if isinstance(nested_auth, dict) and nested_auth.get("type") == "basic":
        username = nested_auth.get("username")
        password = nested_auth.get("password")
        if username is not None:
            aio_auth = aiohttp.BasicAuth(username, password)

    # Set content-type and payload appropriately
    req_headers = {}
    data = None
    json_body = None
    if use_form:
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = creds
    else:
        req_headers["Content-Type"] = "application/json"
        json_body = creds

    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(token_url, data=data, json=json_body, headers=req_headers, auth=aio_auth, ssl=False) as resp:
            text = await resp.text()
            try:
                resp.raise_for_status()
            except Exception as e:
                raise RuntimeError(f"Token request failed ({resp.status}): {text}") from e
            # parse JSON
            try:
                token_data = await resp.json()
            except Exception:
                # fallback: maybe token returned as plain text
                raise RuntimeError(f"Token endpoint did not return JSON: {text}")

    # Extract token
    token_path = auth_cfg.get("token_path", ["access_token"])
    token_val = token_data
    for p in token_path:
        if isinstance(token_val, dict):
            token_val = token_val.get(p)
        else:
            token_val = None
        if token_val is None:
            raise RuntimeError(f"Token path {token_path} not found in token response: {token_data!r}")

    header_name = auth_cfg.get("header", "Authorization")
    prefix = auth_cfg.get("prefix", "")
    headers[header_name] = f"{prefix}{token_val}"
    return headers

async def _start_server_and_list(
    server_name: str,
    params: Dict[str, Any],
    init_timeout: float = 3.0,
    list_timeout: float = 5.0
) -> Tuple[Optional[asyncio.subprocess.Process], Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter],
           List[Dict[str, Any]], bool, Dict[str, Any]]:
    """
    Start a subprocess when transport == 'stdio' and try to call initialize + list methods there.
    If transport is 'http' or 'sse', skip starting a subprocess (we will use MCPClient to list tools later).
    Returns (proc, reader, writer, tools, auth_present, debug_info)
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting server: {server_name}")
    logger.debug(f"Server params: {params}")

    cmd = params.get("command")
    args = params.get("args") or []
    server_env = params.get("env") or {}
    proc_env = os.environ.copy()
    proc_env.update(server_env)

    stderr_lines: List[str] = []
    auth_present, auth_keys = has_auth_env(server_env)
    debug_info: Dict[str, Any] = {"stderr": stderr_lines, "auth_keys_in_server_env": auth_keys}

    transport = params.get("transport", "stdio")

    proc: Optional[asyncio.subprocess.Process] = None
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None

    if transport == "stdio":
        if not cmd:
            error_msg = f"{server_name}: missing command"
            logger.error(error_msg)
            console.print(f"[red]{error_msg}[/red]")
            return None, None, None, [], auth_present, debug_info

        cmd_list = [cmd] + list(args)
        logger.info("Starting process for %s: %s", server_name, shlex.join(cmd_list))

        try:
            # Create process with timeout
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd_list,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=proc_env,
                ),
                timeout=init_timeout
            )
            
            # Check if process started successfully
            if proc.returncode is not None:
                stderr = await proc.stderr.read()
                error_msg = f"Process for {server_name} failed to start with return code {proc.returncode}: {stderr.decode()}"
                logger.error(error_msg)
                return None, None, None, [], auth_present, {'error': error_msg, 'stderr': stderr_lines}
                
        except asyncio.TimeoutError:
            error_msg = f"Timed out after {init_timeout}s while starting server process for {server_name}"
            logger.error(error_msg)
            return None, None, None, [], auth_present, {'error': error_msg, 'stderr': stderr_lines}
        except Exception as e:
            error_msg = f"Failed to start server process for {server_name}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return None, None, None, [], auth_present, {'error': error_msg, 'stderr': stderr_lines}

        reader = proc.stdout
        writer = proc.stdin

        async def drain_stderr(s: asyncio.StreamReader):
            while True:
                line = await s.readline()
                if not line:
                    break
                txt = line.decode(errors="replace").rstrip()
                stderr_lines.append(txt)
                logger.debug("[%s stderr] %s", server_name, txt)

        stderr_task = asyncio.create_task(drain_stderr(proc.stderr))  # type: ignore[arg-type]

        # Initialize JSON-RPC (stdio)
        init_id = next_id()
        init_payload = {
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {
                    "name": "mcpx-local-scan",
                    "version": VERSION,
                    "capabilities": {}
                }
            }
        }
        await send_jsonrpc(writer, init_payload)  # type: ignore[arg-type]
        _ = await recv_json_until(reader, wanted_id=init_id, timeout=init_timeout, want_tools=False)  # type: ignore[arg-type]

        # attach stderr metadata for cleanup
        setattr(proc, "_stderr_task", stderr_task)
        setattr(proc, "_stderr_lines", stderr_lines)

    else:
        logger.info(f"{server_name} using {transport} transport, skipping process spawn")
        #console.print(f" {server_name} using [yellow]{transport}[/yellow] transport")

    # Try listing tools directly for stdio transport
    tools: List[Dict[str, Any]] = []
    list_resp: Optional[Dict[str, Any]] = None

    if transport == "stdio" and reader and writer:
        for method in LIST_METHODS:
            list_id = next_id()
            payload = {"jsonrpc": "2.0", "id": list_id, "method": method, "params": {}}
            await send_jsonrpc(writer, payload)  # type: ignore[arg-type]
            list_resp = await recv_json_until(reader, wanted_id=list_id, timeout=list_timeout, want_tools=True)  # type: ignore[arg-type]
            if list_resp:
                break

    if list_resp:
        result = list_resp.get("result") or {}
        tlist = result.get("tools", [])
        if not tlist and isinstance(result, list):
            tlist = result
        normalized: List[Dict[str, Any]] = []
        for t in tlist:
            if isinstance(t, dict):
                name = t.get("name") or t.get("id") or t.get("tool") or "<unknown>"
                desc = t.get("description") or t.get("desc") or t.get("summary") or ""
                normalized.append({"name": name, "description": desc, "raw": t})
            else:
                normalized.append({"name": str(t), "description": "", "raw": t})
        for n in normalized:
            n["_server_name"] = server_name
        tools = normalized
        logger.info("Enumerated %d tools from %s", len(tools), server_name)
    else:
        if transport == "stdio":
            logger.warning("No tools response from %s", server_name)
            console.print(f"[yellow]{server_name}: no tools returned[/yellow]")

    return proc, reader, writer, tools, auth_present, debug_info


async def scan_server(
    server_name: str,
    params: Dict[str, Any],
    init_timeout: float = 3.0,
    list_timeout: float = 6.0,
    skip_active: bool = False,
    use_dynamic: bool = False,
) -> List[Finding]:
    """
    Scan a single MCP server configuration.

    - supports auth.method == "token" (env/value),
    - supports auth.method == "login" (POST to url + token_path),
    - supports no auth,
    - handles stdio vs http/sse transports.
    """
    logger = logging.getLogger(__name__)
    console.print(f"\n Connecting to server: {server_name}")

    findings: List[Finding] = []

    transport = params.get('transport', 'stdio')
    url = params.get('url')
    headers: Dict[str, str] = dict(params.get('headers', {}) or {})
    auth_cfg: Dict[str, Any] = params.get('auth', {}) 
    #print(auth_cfg) # auth config from JSON

    # ---- Authentication handling ----
    if isinstance(auth_cfg, dict):
        method = str(auth_cfg.get("method", "")).lower()
        if method == "login":
            try:
                headers = await asyncio.wait_for(
                    _perform_login_and_inject_header(auth_cfg, headers),
                    timeout=init_timeout
                )
                logger.info("Performed login token exchange and injected auth header for %s", server_name)
            except asyncio.TimeoutError:
                error_msg = f"Authentication timed out after {init_timeout}s for {server_name}"
                logger.error(error_msg)
                console.print(f"[yellow]{error_msg}[/yellow]")
                return [Finding(
                    server=server_name,
                    unauthenticated=True,
                    tool="auth",
                    description=error_msg,
                    static_risk="info",
                    active_risk="none",
                    matches=[error_msg],
                    proof=json.dumps({
                        'error_type': 'AuthTimeoutError',
                        'error_message': error_msg,
                        'server': server_name
                    })
                )]
            except Exception as e:
                error_msg = f"Failed to perform login/token exchange for {server_name}: {str(e)}"
                logger.error(error_msg, exc_info=True)
                console.print(f"[yellow]{error_msg}[/yellow]")
                # continue without auth header

    # --- Now headers contains the injected Authorization token if login worked ---
    #print("Final headers to use:", headers)

    # ---- Authentication handling (token or login) ----
    auth_token_value: Optional[str] = None
    auth_cfg = params.get('auth', {})
    #print(auth_cfg)
    headers = dict(auth_cfg.get("headers", {}))
    #print(headers)

    # Perform login/token exchange if needed
    if isinstance(auth_cfg, dict) and auth_cfg.get("method") == "login":
        try:
            headers = await _perform_login_and_inject_header(auth_cfg, headers)
            logger.info("Performed login token exchange and injected auth header for %s", server_name)
        except Exception as e:
            logger.error(
                "Failed to perform login/token exchange for %s: %s",
                server_name, str(e),
                exc_info=True
            )

    
    if isinstance(auth_cfg, dict):
        method = str(auth_cfg.get('method', '')).lower()

        if method == 'token':
            # token from environment or direct value
            token = None
            if 'env' in auth_cfg:
                token = os.environ.get(auth_cfg['env'])
                logger.debug("Looking for token in env %s -> %s", auth_cfg['env'], bool(token))
            if not token and 'value' in auth_cfg:
                token = auth_cfg['value']
            if token:
                header_name = auth_cfg.get('header', 'Authorization')
                prefix = auth_cfg.get('prefix', '')
                headers[header_name] = f"{prefix}{token}"
                auth_token_value = token
                logger.info("Using token auth for %s via header %s", server_name, header_name)
            else:
                logger.warning("auth.method=token but token not found (env/value) for %s", server_name)

        elif method == 'login':
            # For OAuth2 login, we'll handle it in the MCP client's connect method
            # Just make sure auth_cfg is properly passed through
            if transport in ('http', 'sse') and url:
                try:
                    from .mcp_client import MCPClient
                    mcp_headers = headers.copy()
                    
                    # Initialize MCP client first without auth headers
                    logger.info(f"Initializing MCP client for {server_name}")
                    mcp = MCPClient(
                        transport=transport,
                        reader=None,
                        writer=None,
                        url=url,
                        headers=mcp_headers
                    )
                    
                    # Handle OAuth2 authentication if configured
                    if auth_cfg and auth_cfg.get('method') == 'login':
                        logger.info(f"Initiating OAuth2 flow for {server_name}")
                        await mcp.connect(auth_config=auth_cfg)
                    # Handle token-based auth if provided
                    elif auth_token and 'Authorization' not in mcp_headers and auth_header_key:
                        mcp_headers['Authorization'] = auth_token
                        logger.info(f"Using provided token for {server_name}")
                        mcp = MCPClient(
                            transport=transport,
                            reader=None,
                            writer=None,
                            url=url,
                            headers=mcp_headers
                        )
                        await mcp.connect()
                    else:
                        logger.info("No authentication configured, proceeding without auth")
                        await mcp.connect()
                        
                except Exception as e:
                    logger.error("Failed to initialize MCPClient for %s: %s", server_name, str(e), exc_info=True)
                    raise

        else:
            logger.debug("Unknown auth method '%s' for %s — skipping auth step", method, server_name)

    # store a simple auth token string (if Authorization header present)
    auth_header_key = None
    for k, v in headers.items():
        if k.lower() == 'authorization':
            auth_header_key = k
            break
    auth_token = headers.get(auth_header_key) if auth_header_key else None

    # ---- Start server and initial listing for stdio transport ----
    proc, reader, writer, tools, auth_present, debug_info = await _start_server_and_list(
        server_name, params, init_timeout=init_timeout, list_timeout=list_timeout
    )

    # ---- If HTTP/SSE, create MCP client and list tools with headers ----
    mcp = None
    if transport in ('http', 'sse'):
        try:
            from .mcp_client import MCPClient
            mcp_headers = headers.copy()
            
            # Log authentication configuration
            logger.debug(f"Auth config for {server_name}: {auth_cfg}")
            
            # Initialize MCP client with initial headers
            logger.info(f"Initializing MCP client for {server_name}")
            mcp = MCPClient(
                transport=transport,
                reader=reader,
                writer=writer,
                url=url,
                headers=mcp_headers
            )
            
            # Handle OAuth2 authentication if configured
            if isinstance(auth_cfg, dict) and auth_cfg.get('method') == 'login':
                logger.info(f"Initiating OAuth2 flow for {server_name}")
                try:
                    # Pass the entire auth config to the connect method
                    await mcp.connect(auth_config=auth_cfg)
                    logger.info("OAuth2 authentication successful")
                except Exception as e:
                    logger.error(f"OAuth2 authentication failed: {str(e)}", exc_info=True)
                    raise
            # Handle token-based auth if provided
            elif auth_token and 'Authorization' not in mcp_headers and auth_header_key:
                mcp_headers['Authorization'] = auth_token
                logger.info(f"Using provided token for {server_name}")
                mcp = MCPClient(
                    transport=transport,
                    reader=reader,
                    writer=writer,
                    url=url,
                    headers=mcp_headers
                )
                await mcp.connect()
            else:
                logger.info("No authentication configured, proceeding without auth")
                await mcp.connect()
                
        except Exception as e:
            logger.error("Failed to initialize MCPClient for %s: %s", server_name, str(e), exc_info=True)
            raise

    # ---- If no tools from _start_server_and_list, try to enumerate using client or stdio fallback ----
    if not tools:
        logger.info("Attempting to list tools using client")
        
        # For the new MCPClient that uses official MCP library, tools are already listed during connect
        if transport in ('http', 'sse') and mcp and hasattr(mcp, 'get_tools'):
            tools = mcp.get_tools()
            logger.info("Found %d tools via MCPClient.get_tools()", len(tools))
        else:
            # Fallback to old method for stdio or if MCPClient doesn't have get_tools
            methods_to_try: List[Tuple[str, Dict[str, Any]]] = [
                ('tools/list', {}),
                ('list_tools', {}),
                ('tools.list', {}),
                ('listTools', {}),
            ]

            for method_name, payload in methods_to_try:
                if tools:
                    break
                try:
                    logger.info("Trying method: %s", method_name)
                    if transport in ('http', 'sse') and mcp and hasattr(mcp, 'call_tool'):
                        list_result = await mcp.call_tool(method_name, payload)
                    elif transport == 'stdio' and reader and writer:
                        req_id = next_id()
                        await send_jsonrpc(writer, {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "method": method_name,
                            "params": payload
                        })
                        list_result = await recv_json_until(reader, wanted_id=req_id, timeout=list_timeout, want_tools=True)

                    else:
                        list_result = None

                    logger.debug("List tools (%s) result: %s", method_name, list_result)

                    if isinstance(list_result, dict):
                        if 'result' in list_result:
                            result = list_result['result']
                            if isinstance(result, dict) and 'tools' in result:
                                tools = result['tools']
                                logger.info("Found %d tools via '%s' (nested tools key)", len(tools), method_name)
                            elif isinstance(result, list):
                                tools = result
                                logger.info("Found %d tools via '%s' (direct list result)", len(tools), method_name)
                        elif 'error' in list_result:
                            err_msg = list_result.get('error', {}).get('message', 'Unknown error')
                            logger.warning("Error from %s: %s", method_name, err_msg)
                except Exception as e:
                    logger.warning("Failed to list tools with method '%s': %s", method_name, str(e), exc_info=True)

    # ---- Get resources if available ----
    resources = []
    if transport in ('http', 'sse') and mcp and hasattr(mcp, 'get_resources'):
        resources = mcp.get_resources()
        logger.info("Found %d resources via MCPClient.get_resources()", len(resources))
    elif transport == 'stdio' and reader and writer:
        # Try to list resources for stdio transport
        try:
            req_id = next_id()
            await send_jsonrpc(writer, {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "resources/list",
                "params": {}
            })
            resources_result = await recv_json_until(reader, wanted_id=req_id, timeout=list_timeout, want_resources=True)
            if isinstance(resources_result, dict) and 'result' in resources_result:
                result = resources_result['result']
                if isinstance(result, dict) and 'resources' in result:
                    resources = result['resources']
                    logger.info("Found %d resources via stdio", len(resources))
        except Exception as e:
            logger.warning("Failed to list resources via stdio: %s", str(e))

    # ---- If we expected a subprocess for stdio but proc missing => failed to start ----
    if transport == "stdio" and not proc:
        console.print(f"[red]{server_name}: failed to start[/red]")
        return findings

    # Initialize client variable for SSE transport
    client = None
    if transport == "sse" and not tools:
        try:
            from mcp_analyzer.mcp_client import MCPClient
            client = MCPClient(transport="sse", url=url, headers=headers)
            await client.connect()
            # Tools are already listed during connect with the new MCPClient
            tools = client.get_tools()
            logger.info("Listed %d tools from SSE server", len(tools) if tools else 0)
        except Exception as e:
            logger.warning("Failed to initialize SSE client: %s", str(e))
            client = None

    # ---- Determine authentication status ----
    unauthenticated = False
    auth_type = "none"
    
    # Check if this is an OAuth server based on config
    is_oauth = 'auth' in params and params['auth'].get('method') == 'login' and 'token_path' in params['auth']
    
    if tools:
        if is_oauth:
            # For OAuth, if we got tools, it means authentication was successful
            auth_type = "OAuth"
            #console.print(f"  Authenticated via OAuth)
            logger.info("[PROOF] %s authenticated via OAuth → tools/list succeeded", server_name)
        elif not auth_present:
            # No auth configured and we got tools
            auth_type = "none"
            unauthenticated = True
            #console.print(f"[red]Unauthenticated access: YES for {server_name}[/red] (no auth configured)")
            logger.info("[PROOF] %s unauthenticated → tools/list OK, no auth configured", server_name)
        else:
            # Other auth types (token, basic, etc.)
            auth_type = params.get('auth', {}).get('method', 'unknown')
            #console.print(f"[green]Authenticated via {auth_type}: YES for {server_name}[/green]")
            logger.info("[PROOF] %s authenticated via %s → tools/list OK", server_name, auth_type)
    else:
        # No tools listed - could be auth failure or no tools available
        if is_oauth:
            console.print(f"[yellow]OAuth authentication may have failed for {server_name} - no tools listed[/yellow]")
        logger.info("[PROOF] %s no tools listed → auth_type: %s, server_env auth keys: %s",
                   server_name, auth_type, debug_info.get("auth_keys_in_server_env"))

    # Print authentication status and tools
    if is_oauth or (tools and not unauthenticated):
        console.print("  [green]Authenticated[/green]")
    else:
        console.print("  [red]Unauthenticated[/red]")
        
    # Display tools and resources in mcp-scan style format
    from .classify import detect_prompt_injection
    
    # Display resources first
    if resources:
        console.print("  Resources:")
        for r in resources:
            if isinstance(r, dict):
                name = r.get('name') or r.get('id') or r.get('uri') or "<unknown>"
                desc = r.get('description') or ""
                uri = r.get('uri') or ""
                
                # Debug: Log the resource data
                logger.debug(f"Resource data: {r}")
                
                # Check for prompt injection in resource description
                has_injection, injection_patterns = detect_prompt_injection(desc)
                
                # Also try to read the resource content and check for prompt injection there
                resource_content = ""
                if uri and transport in ('http', 'sse') and mcp and hasattr(mcp, 'read_resource'):
                    # Check if content was already read during connection
                    if 'content' in r and r.get('content'):
                        resource_content = r.get('content')
                        logger.debug(f"Using pre-read resource content for {name}: {resource_content[:200]}...")
                    else:
                        # Fallback: try to read now (may fail if session is closed)
                        try:
                            resource_result = await mcp.read_resource(str(uri))
                            if hasattr(resource_result, 'contents'):
                                resource_content = resource_result.contents[0].text if resource_result.contents else ""
                            elif isinstance(resource_result, str):
                                resource_content = resource_result
                            logger.debug(f"Resource content for {name}: {resource_content[:200]}...")
                        except Exception as e:
                            logger.debug(f"Failed to read resource {name}: {str(e)}", exc_info=True)
                    
                    # Check for prompt injection in resource content
                    if resource_content:
                        content_has_injection, content_patterns = detect_prompt_injection(resource_content)
                        if content_has_injection:
                            has_injection = True
                            injection_patterns.extend(content_patterns)
                
                if has_injection:
                    console.print(f"    [red]❌ [E001]: Prompt injection detected in the resource.[/red]")
                    if desc:
                        console.print(f"    [yellow]Description:[/yellow] {desc}")
                    if resource_content:
                        console.print(f"    [yellow]Content:[/yellow] {resource_content[:200]}...")
                    console.print(f"    [yellow]Detected patterns:[/yellow] {', '.join(set(injection_patterns))}")
                else:
                    console.print(f"    [green]✅[/green] {name}")
            else:
                console.print(f"    [green]✅[/green] {str(r)}")
    else:
        console.print("  [yellow]No resources found[/yellow]")
    
    # Display tools
    if tools:
        console.print("  Tools:")
        for t in tools:
            if isinstance(t, dict):
                name = t.get('name') or t.get('id') or t.get('tool') or "<unknown>"
                desc = t.get('description') or t.get('desc') or t.get('summary') or ""
                
                # Check for prompt injection in tool description
                has_injection, injection_patterns = detect_prompt_injection(desc)
                
                if has_injection:
                    console.print(f"    [red]❌ [E001]: Prompt injection detected in the tool description.[/red]")
                    console.print(f"    [yellow]Current description:[/yellow]")
                    console.print(f"    {desc}")
                    console.print(f"    [yellow]Detected patterns:[/yellow] {', '.join(injection_patterns)}")
                else:
                    console.print(f"    [green]✅[/green] {name}")
            else:
                console.print(f"    [green]✅[/green] {str(t)}")
    else:
        console.print(f"[yellow]  No tools enumerated[/yellow]")

    # ---- Normalize tools list into dicts with name/description/raw ----
    normalized_tools: List[Dict[str, Any]] = []
    for t in tools:
        if isinstance(t, dict):
            name = t.get('name') or t.get('id') or t.get('tool') or "<unknown>"
            desc = t.get('description') or t.get('desc') or t.get('summary') or ""
            normalized_tools.append({"name": name, "description": desc, "raw": t})
        else:
            normalized_tools.append({"name": str(t), "description": "", "raw": t})

    # ---- For HTTP transport choose mcp client; for stdio, create SimpleMCPClient if needed ----
    for t in normalized_tools:
        tname = t.get("name", "<unknown>")
        tdesc = t.get("description", "") or ""
        raw = t.get("raw") or {}
        static_risk, matches = static_classify(tname, tdesc, raw)

        finding = Finding(
            server=server_name,
            unauthenticated=unauthenticated,
            tool=tname,
            description=tdesc,
            static_risk=static_risk,
            active_risk="none",
            matches=matches,
            probe_results={},
            proof=None
        )

        if unauthenticated and not skip_active:
            # choose mcp_client
            if transport in ('http', 'sse') and mcp:
                mcp_client = mcp
            else:
                # fallback SimpleMCPClient for stdio
                class SimpleMCPClient:
                    def __init__(self, reader, writer, headers=None):
                        self.reader = reader
                        self.writer = writer
                        self.headers = headers or {}

                    async def call_tool(self, tool_name, payload):
                        request_id = next_id()
                        await send_jsonrpc(self.writer, {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": tool_name,
                            "params": payload
                        })
                        return await recv_json_until(self.reader, request_id, timeout=5.0)

                mcp_client = SimpleMCPClient(reader, writer, headers)

            try:
                # Execute relevant probes for this tool
                probe_results = await execute_probes(t, mcp_client, use_dynamic=use_dynamic)
                
                # Update finding with probe results
                if probe_results:
                    finding.probe_results = probe_results
                    
                    # Update active risk based on probe results
                    for probe_type, result in probe_results.items():
                        if result.get('success'):
                            if probe_type == ProbeType.FILE_READ.value:
                                active_risk = max(active_risk, "high" if result.get('confidence', 0) > 0.8 else "medium")
                            elif probe_type == ProbeType.COMMAND_EXEC.value:
                                active_risk = max(active_risk, "critical" if result.get('confidence', 0) > 0.8 else "high")
                            
                            # Store proof if available
                            if 'proof' in result and result['proof']:
                                finding.proof = result['proof']
            except Exception as e:
                logger.error("Error during probe execution for %s on %s: %s", tname, server_name, str(e), exc_info=True)
                error_proof = f"Error during probe execution: {str(e)}"
                finding.proof = error_proof

                if isinstance(error_proof, str) and error_proof.startswith('{') and error_proof.endswith('}'):
                    try:
                        json.loads(proof)
                        finding.proof = proof
                    except Exception:
                        finding.proof = json.dumps({
                            "tool_name": tname,
                            "server": server_name,
                            "response": str(proof)[:500],
                            "classification": "normal_behavior"
                        }, indent=2)
                else:
                    finding.proof = json.dumps({
                        "tool_name": tname,
                        "server": server_name,
                        "response": str(proof or "")[:500],
                        "classification": "normal_behavior"
                    }, indent=2)

                if pr_exec.get("is_tool_poisoning", False):
                    finding.active_risk = "critical"
                    finding.matches.append("tool_poisoning:command_exec")

            if finding.active_risk == "none" and static_risk == "dangerous":
                finding.active_risk = "medium"
        else:
            if static_risk == "dangerous":
                finding.active_risk = "medium"
            elif static_risk == "suspicious":
                finding.active_risk = "low"
            else:
                finding.active_risk = "none"

        findings.append(finding)

    # ---- Cleanup spawned process (if any) ----
    if proc is not None:
        try:
            if proc.returncode is None:
                proc.terminate()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except Exception:
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
        try:
            stderr_task = getattr(proc, "_stderr_task", None)
            if stderr_task:
                stderr_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await stderr_task
        except Exception:
            pass

    return findings


# Optional CLI: keep for quick testing. Your scan.py may call scan_server directly.
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description="Run MCP scanner for a config file")
    parser.add_argument("config", nargs="?", default="test.json", help="Path to config JSON")
    parser.add_argument("--init-timeout", type=float, default=3.0)
    parser.add_argument("--list-timeout", type=float, default=6.0)
    parser.add_argument("--skip-active-probes", action="store_true")
    args = parser.parse_args()

    async def _main():
        if not os.path.exists(args.config):
            console.print(f"[red]Config file {args.config} not found[/red]")
            return
        with open(args.config) as fh:
            cfg = json.load(fh)
        servers = cfg.get("mcpServers", {})
        all_findings: List[Finding] = []
        for name, conf in servers.items():
            try:
                f = await scan_server(
                    name, 
                    conf, 
                    init_timeout=args.init_timeout, 
                    list_timeout=args.list_timeout, 
                    skip_active=args.skip_active_probes,
                    use_dynamic=getattr(args, 'use_dynamic', False)
                )
                all_findings.extend(f)
            except Exception as e:
                logger.error("Error scanning %s: %s", name, str(e), exc_info=True)
        console.rule("[bold green]Findings[/bold green]")
        if not all_findings:
            console.print("No vulnerabilities found!")
        else:
            for fa in all_findings:
                console.print(f"- {fa}")

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
