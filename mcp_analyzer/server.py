from __future__ import annotations
import asyncio, os, shlex, logging, contextlib
from typing import Any, Dict, List, Tuple
from rich.console import Console
from .auth import has_auth_env
from .rpc import send_jsonrpc, recv_json_until, next_id
from .constants import VERSION, LIST_METHODS
from .classify import static_classify
from .findings import Finding
from .probes import probe_file_read, probe_exec

console = Console()

async def _start_server_and_list(
    server_name: str,
    params: Dict[str, Any],
    init_timeout=3.0,
    list_timeout=5.0
) -> Tuple[Any, Any, Any, List[Dict[str, Any]], bool, Dict[str, Any]]:
    cmd = params.get("command")
    args = params.get("args") or []
    server_env = params.get("env") or {}
    proc_env = os.environ.copy()
    proc_env.update(server_env)

    stderr_lines: List[str] = []

    auth_present, auth_keys = has_auth_env(server_env)
    debug_info: Dict[str, Any] = {"stderr": stderr_lines, "auth_keys_in_server_env": auth_keys}

    if not cmd:
        console.print(f"[red]{server_name}: missing command[/red]")
        return None, None, None, [], auth_present, debug_info

    cmd_list = [cmd] + list(args)
    logging.info("Starting process for %s: %s", server_name, shlex.join(cmd_list))

    proc = await asyncio.create_subprocess_exec(
        *cmd_list,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=proc_env,
    )

    reader = proc.stdout
    writer = proc.stdin

    async def drain_stderr(s: asyncio.StreamReader):
        while True:
            line = await s.readline()
            if not line:
                break
            txt = line.decode(errors="replace").rstrip()
            stderr_lines.append(txt)
            logging.debug("[%s stderr] %s", server_name, txt)

    stderr_task = asyncio.create_task(drain_stderr(proc.stderr))

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
    await send_jsonrpc(writer, init_payload)
    _ = await recv_json_until(reader, wanted_id=init_id, timeout=init_timeout, want_tools=False)

    tools: List[Dict[str, Any]] = []
    list_resp = None
    for method in LIST_METHODS:
        list_id = next_id()
        payload = {"jsonrpc": "2.0", "id": list_id, "method": method, "params": {}}
        await send_jsonrpc(writer, payload)
        list_resp = await recv_json_until(reader, wanted_id=list_id, timeout=list_timeout, want_tools=True)
        if list_resp:
            break

    if list_resp:
        result = list_resp.get("result") or {}
        tlist = result.get("tools", [])
        if not tlist and isinstance(result, list):
            tlist = result
        normalized = []
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
        logging.info("Enumerated %d tools from %s", len(tools), server_name)
        console.print(f"[green]{server_name} tools:[/green] {', '.join([t['name'] for t in tools])}")
    else:
        logging.warning("No tools response from %s", server_name)
        console.print(f"[yellow]{server_name}: no tools returned[/yellow]")

    proc._stderr_task = stderr_task  # type: ignore
    proc._stderr_lines = stderr_lines  # type: ignore

    return proc, reader, writer, tools, auth_present, debug_info

async def scan_server(
    server_name: str,
    params: Dict[str, Any],
    init_timeout: float = 3.0,
    list_timeout: float = 6.0,
    skip_active: bool = False,
) -> List[Finding]:
    from .constants import LOG_FILE  # ensure logging is configured once by reporter or entry
    console.print(f"[cyan]Connecting to server:[/cyan] {server_name}")

    findings: List[Finding] = []

    proc, reader, writer, tools, auth_present, debug_info = await _start_server_and_list(
        server_name, params, init_timeout=init_timeout, list_timeout=list_timeout
    )

    if not proc:
        console.print(f"[red]{server_name}: failed to start[/red]")
        return findings

    unauthenticated = (not auth_present) and bool(tools)

    if unauthenticated:
        console.print(f"[red]Unauthenticated access: YES for {server_name}[/red] "
              f"(tools/list succeeded and no auth env keys supplied)")
        logging.info("[PROOF] %s unauthenticated → tools/list OK, server_env auth keys: %s",
             server_name, debug_info.get("auth_keys_in_server_env"))
    else:
        logging.info("[PROOF] %s authenticated or unavailable → server_env auth keys: %s",
             server_name, debug_info.get("auth_keys_in_server_env"))

    console.print(f"  Unauthenticated: {'YES' if unauthenticated else 'NO'}")
    if tools:
        console.print(f"  Tools: {', '.join([t['name'] for t in tools])}")
    else:
        console.print(f"[yellow]  No tools enumerated[/yellow]")

    for t in tools:
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
            text = f"{tname} {tdesc}".lower()
            did_probe = False
            
            # Create MCP client wrapper
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

            # Always test for file read vulnerabilities first
            pr_file = await probe_file_read(mcp_client, t)
            did_probe = True
            finding.probe_results["file_read"] = pr_file
            
            if pr_file and isinstance(pr_file, Finding) and pr_file.proof:
                finding.active_risk = "high"
                finding.proof = (pr_file.proof or "")[:160]
                finding.matches.append("tool_poisoning:file_read")
            elif isinstance(pr_file, dict) and pr_file.get("proof"):
                finding.active_risk = "high"
                finding.proof = (pr_file.get("proof") or "")[:160]
                finding.matches.append("tool_poisoning:file_read")
            
            # Then test for command execution vulnerabilities
            pr_exec = await probe_exec(server_name, t, reader, writer)
            finding.probe_results["exec"] = pr_exec
            
            if pr_exec and isinstance(pr_exec, dict) and pr_exec.get("success"):
                finding.active_risk = "critical"
                finding.proof = (pr_exec.get("proof") or "")[:160]
                finding.matches.append("tool_poisoning:command_exec")
            elif isinstance(pr_exec, Finding) and pr_exec.proof:
                finding.active_risk = "critical"
                finding.proof = (pr_exec.proof or "")[:160]
                finding.matches.append("tool_poisoning:command_exec")
            
            # If no vulnerabilities found but tool is marked as dangerous, keep medium risk
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

    # Cleanup
    try:
        if proc.returncode is None:
            proc.terminate()
    except Exception:
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            await proc.wait()
        except Exception:
            pass
    try:
        if getattr(proc, "_stderr_task", None):
            proc._stderr_task.cancel()  # type: ignore
            with contextlib.suppress(asyncio.CancelledError):
                await proc._stderr_task  # type: ignore
    except Exception:
        pass

    return findings
