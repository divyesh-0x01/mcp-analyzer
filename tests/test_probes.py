# Probe functions rely on live MCP server; here we only check helpers that are pure.
from mcp_analyzer.probes import looks_like_passwd, extract_result_text

def test_looks_like_passwd():
    assert looks_like_passwd("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash")

def test_extract_result_text_plain():
    resp = {"result": {"text": "hello"}}
    assert extract_result_text(resp) == "hello"
