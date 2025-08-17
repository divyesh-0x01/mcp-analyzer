from mcp_analyzer.config import load_config
import json, tempfile, os

def test_load_config_ok():
    cfg = {"mcpServers": {"s1": {"command": "echo", "args": ["ok"], "env": {"API_KEY":"x"}}}}
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(cfg, f); path = f.name
    try:
        servers = load_config(path)
        assert "s1" in servers
        assert servers["s1"]["command"] == "echo"
    finally:
        os.unlink(path)
