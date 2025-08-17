from __future__ import annotations

VERSION = "mcpx-local-scan-2.0-active-probes-proof"
LOG_FILE = "scan_debug.log"
OUT_JSON = "scan_results.json"

COMMON_AUTH_KEYS = [
    "API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY",
    "TOKEN", "AUTH_TOKEN", "BEARER_TOKEN", "ACCESS_TOKEN",
    "SLACK_BOT_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
    "HF_TOKEN", "HUGGINGFACE_TOKEN", "GITHUB_TOKEN", "PERSONAL_ACCESS_TOKEN"
]

DANGEROUS_PATTERNS = {
    "file_ops": ["read_file", "read", "file", "filesystem", "fs", "cat", "open", "download"],
    "exec": ["exec", "system", "shell", "cmd", "command", "run", "subprocess"],
    "network": ["http", "fetch", "request", "socket", "connect", "net", "upload"],
    "secrets": ["secret", "token", "password", "key", "credential", "private_key"],
    "admin": ["root", "sudo", "admin", "privilege", "grant"]
}

COMMON_PATH_KEYS = ["path", "filepath", "filename", "file", "target", "src", "source"]
COMMON_CMD_KEYS = ["cmd", "command", "command_line", "shell", "exec", "program", "commandStr"]
COMMON_ARG_FOR_POSITIONAL = ["args", "argv", "params", "arguments"]
UNIX_SENSITIVE = "/etc/passwd"
WIN_SENSITIVE = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
BENIGN_CMD = "hostname"
BENIGN_CMD_ALT = "whoami"

LIST_METHODS = ["tools/list", "list_tools"]
CALL_METHODS = ["tools/call", "tool/call", "call_tool", "call", "invoke"]
