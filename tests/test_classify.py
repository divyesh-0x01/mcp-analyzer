from mcp_analyzer.classify import static_classify

def test_static_classify_file():
    risk, matches = static_classify("read_file", "reads a file", {"inputSchema": {"properties": {"path": {"description":"path"}}}})
    assert risk in ("suspicious","dangerous")
    assert any("file_ops" in m for m in matches)
