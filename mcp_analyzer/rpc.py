from __future__ import annotations
import asyncio, json, logging, re
from typing import Optional

_id_counter = 1
def next_id():
    global _id_counter
    _id_counter += 1
    return _id_counter

async def send_jsonrpc(writer: asyncio.StreamWriter, payload: dict) -> None:
    raw = json.dumps(payload) + "\n"
    logging.debug("SEND: %s", raw.strip()[:4000])
    writer.write(raw.encode())
    try:
        await writer.drain()
    except Exception:
        pass

async def recv_json_until(reader: asyncio.StreamReader, wanted_id: Optional[int], timeout: float, want_tools: bool = False) -> Optional[dict]:
    """
    Reads lines until we find a JSON-RPC message that either:
      - matches wanted_id, OR
      - (want_tools=True) includes result.tools
    Returns the parsed object or None on timeout/EOF.
    """
    end_at = asyncio.get_event_loop().time() + timeout
    buf = ""
    while True:
        remaining = end_at - asyncio.get_event_loop().time()
        if remaining <= 0:
            return None
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=remaining)
        except asyncio.TimeoutError:
            return None
        if not line:
            return None
        text = line.decode(errors="replace").strip()
        logging.debug("RECV: %s", text[:4000])
        buf += text + "\n"
        # direct parse
        try:
            obj = json.loads(text)
            if wanted_id is not None and obj.get("id") == wanted_id:
                return obj
            if want_tools and isinstance(obj.get("result"), dict) and "tools" in obj["result"]:
                return obj
        except Exception:
            pass
        # find object in buffer
        m = re.search(r"(\{.*\})", buf, flags=re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(1))
                if wanted_id is not None and obj.get("id") == wanted_id:
                    return obj
                if want_tools and isinstance(obj.get("result"), dict) and "tools" in obj["result"]:
                    return obj
            except Exception:
                pass
