import pytest
from unittest.mock import AsyncMock, MagicMock
from mcp_analyzer.probes import (
    looks_like_passwd, 
    extract_result_text,
    analyze_sql_injection_response,
    analyze_xss_response,
    ProbeType,
    ParameterType,
    get_parameter_type
)

# Helper function to create a mock tool
def create_mock_tool(name, description, params=None):
    return {
        "name": name,
        "description": description,
        "parameters": params or {}
    }

def test_looks_like_passwd():
    assert looks_like_passwd("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash")

def test_extract_result_text_plain():
    resp = {"result": {"text": "hello"}}
    assert extract_result_text(resp) == "hello"

# SQL Injection Tests
def test_analyze_sql_injection_response_positive():
    """Test SQL injection detection with a positive case."""
    response = "Error: SQL syntax error near 'SELECT * FROM users'"
    assert analyze_sql_injection_response(response) is True

def test_analyze_sql_injection_response_negative():
    """Test SQL injection detection with a negative case."""
    response = "Success: Record found"
    assert analyze_sql_injection_response(response) is False

def test_analyze_sql_injection_response_with_suspicious_phrases():
    """Test SQL injection detection with suspicious phrases."""
    response = "Invalid SQL syntax: unexpected token near 'WHERE'"
    assert analyze_sql_injection_response(response) is True

# XSS Tests
def test_analyze_xss_response_positive():
    """Test XSS detection with a positive case."""
    payload = "<script>alert(1)</script>"
    response = f"Error: Invalid input: {payload}"
    assert analyze_xss_response(response, payload) is True

def test_analyze_xss_response_negative():
    """Test XSS detection with a negative case."""
    payload = "<script>alert(1)</script>"
    response = "Error: Invalid input"  # Payload not reflected
    assert analyze_xss_response(response, payload) is False

def test_analyze_xss_response_with_encoded_payload():
    """Test XSS detection with encoded payload."""
    payload = "<script>alert(1)</script>"
    encoded_payload = "&lt;script&gt;alert(1)&lt;/script&gt;"
    response = f"Error: {encoded_payload}"
    assert analyze_xss_response(response, payload) is True

# Parameter Type Detection Tests
def test_get_parameter_type_sql_query():
    """Test detection of SQL query parameters."""
    assert get_parameter_type("query") == ParameterType.SQL_QUERY
    assert get_parameter_type("sql_query") == ParameterType.SQL_QUERY
    assert get_parameter_type("search_query") == ParameterType.SQL_QUERY

def test_get_parameter_type_sql_filter():
    """Test detection of SQL filter parameters."""
    assert get_parameter_type("filter") == ParameterType.SQL_FILTER
    assert get_parameter_type("where_clause") == ParameterType.SQL_FILTER
    assert get_parameter_type("order_by") == ParameterType.SQL_FILTER

def test_get_parameter_type_html_input():
    """Test detection of HTML input parameters."""
    assert get_parameter_type("html") == ParameterType.HTML_INPUT
    assert get_parameter_type("content") == ParameterType.HTML_INPUT
    assert get_parameter_type("body") == ParameterType.HTML_INPUT

# Integration Tests (using mocks)
@pytest.mark.asyncio
async def test_sql_injection_probe_with_vulnerable_tool():
    """Test SQL injection probe with a vulnerable tool."""
    from mcp_analyzer.probes import probe_sql_injection
    
    # Create a mock MCP client
    mock_client = AsyncMock()
    mock_client.call_tool = AsyncMock(return_value={"result": {"text": "SQL syntax error"}})
    
    # Create a vulnerable tool with SQL-related parameters
    tool = create_mock_tool(
        "query_database",
        "Runs SQL queries on the database",
        {
            "query": {"type": "string", "description": "SQL query to execute"},
            "limit": {"type": "integer", "description": "Max number of results"}
        }
    )
    
    # Run the probe
    result = await probe_sql_injection(mock_client, tool)
    
    # Verify the result
    assert result["success"] is True
    assert "SQL injection" in result["proof"]
    assert result["confidence"] >= 0.9

@pytest.mark.asyncio
async def test_xss_probe_with_vulnerable_tool():
    """Test XSS probe with a vulnerable tool."""
    from mcp_analyzer.probes import probe_xss
    
    # Create a mock MCP client
    mock_client = AsyncMock()
    xss_payload = "<script>alert(1)</script>"
    mock_client.call_tool = AsyncMock(return_value={"result": {"text": f"Error: {xss_payload}"}})
    
    # Create a vulnerable tool with HTML input parameters
    tool = create_mock_tool(
        "render_html",
        "Renders HTML content",
        {
            "content": {"type": "string", "description": "HTML content to render"},
            "title": {"type": "string", "description": "Page title"}
        }
    )
    
    # Run the probe
    result = await probe_xss(mock_client, tool)
    
    # Verify the result
    assert result["success"] is True
    assert "XSS" in result["proof"]
    assert result["confidence"] >= 0.9
