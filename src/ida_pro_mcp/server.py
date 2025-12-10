import os
import sys
import json
import shutil
import argparse
import http.client
import tempfile
import traceback
import tomllib
import tomli_w
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import TYPE_CHECKING
from urllib.parse import urlparse
import glob

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)  # Clean up

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337
MAIN_SERVER_PORT = 13337

# Registry of connected IDA instances
# Key: sha256 hash, Value: instance metadata
IDA_INSTANCES: dict[str, dict] = {}
_instances_lock = threading.Lock()

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


def find_instance(binary: str) -> dict | None:
    """Find an IDA instance by binary identifier (sha256, module name, or path)"""
    with _instances_lock:
        # 1. Try sha256 hash first
        if binary in IDA_INSTANCES:
            return IDA_INSTANCES[binary]

        # 2. Try module name
        for instance in IDA_INSTANCES.values():
            if instance.get("module") == binary:
                return instance

        # 3. Try path partial match
        for instance in IDA_INSTANCES.values():
            if binary in instance.get("path", ""):
                return instance

        return None


def get_instance_count() -> int:
    """Get the number of registered instances"""
    with _instances_lock:
        return len(IDA_INSTANCES)


def get_single_instance() -> dict | None:
    """Get the single registered instance (if exactly one)"""
    with _instances_lock:
        if len(IDA_INSTANCES) == 1:
            return list(IDA_INSTANCES.values())[0]
        return None


def forward_to_instance(request_data: bytes, host: str, port: int) -> dict:
    """Forward a request to an IDA instance"""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request("POST", "/mcp", request_data, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read().decode()
        return json.loads(data)
    finally:
        conn.close()


def add_binary_param_to_schema(response: dict) -> dict:
    """Add 'binary' parameter to all tool schemas and add list_instances tool"""
    if "result" not in response or "tools" not in response["result"]:
        return response

    # Add binary parameter to all tools from IDA
    for tool in response["result"]["tools"]:
        if "inputSchema" in tool and "properties" in tool["inputSchema"]:
            tool["inputSchema"]["properties"]["binary"] = {
                "type": "string",
                "description": "Target binary (name like 'binary.exe', sha256 hash, or path). Use list_instances to see available binaries.",
            }

    # Add list_instances tool (main server tool)
    list_instances_tool = {
        "name": "list_instances",
        "description": "List all connected IDA Pro instances with their binary information",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    }

    # Check if list_instances already exists
    existing_names = {tool["name"] for tool in response["result"]["tools"]}
    if "list_instances" not in existing_names:
        response["result"]["tools"].append(list_instances_tool)

    return response


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry"""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj["method"]

    # Handle locally: initialize, notifications
    if method == "initialize":
        return dispatch_original(request)
    elif method.startswith("notifications/"):
        return dispatch_original(request)

    # Handle list_instances locally (it's a main server tool)
    if method == "tools/call":
        params = request_obj.get("params", {})
        if isinstance(params, dict) and params.get("name") == "list_instances":
            return dispatch_original(request)

    # Handle tools/list - try to discover instances if none registered
    if method == "tools/list":
        if get_instance_count() == 0:
            discover_ida_instances(IDA_HOST)

        if get_instance_count() == 0:
            # Still no instances - return only list_instances tool
            request_id = request_obj.get("id")
            return {
                "jsonrpc": "2.0",
                "result": {
                    "tools": [
                        {
                            "name": "list_instances",
                            "description": "List all connected IDA Pro instances with their binary information. No IDA instances are currently connected.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                                "required": [],
                            },
                        }
                    ]
                },
                "id": request_id,
            }

        # Get tools from the first available instance (all instances have same tools)
        with _instances_lock:
            first_instance = list(IDA_INSTANCES.values())[0]
        try:
            request_data = json.dumps(request_obj).encode("utf-8")
            response = forward_to_instance(request_data, first_instance["host"], first_instance["port"])
            return add_binary_param_to_schema(response)
        except Exception as e:
            request_id = request_obj.get("id")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": f"Failed to get tools: {e}"},
                "id": request_id,
            }

    # Extract binary parameter for routing
    # For tools/call, binary is in params.arguments
    # For other methods, binary might be directly in params
    params = request_obj.get("params", {})
    binary = None
    if isinstance(params, dict):
        if method == "tools/call" and "arguments" in params:
            arguments = params.get("arguments", {})
            if isinstance(arguments, dict):
                binary = arguments.pop("binary", None)
        else:
            binary = params.pop("binary", None)

    # Determine target instance
    target_host = IDA_HOST
    target_port = IDA_PORT
    instance = None

    if binary:
        instance = find_instance(binary)
        if not instance:
            request_id = request_obj.get("id")
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"No IDA instance found for binary: {binary}. Use list_instances to see available binaries.",
                },
                "id": request_id,
            }
        target_host = instance["host"]
        target_port = instance["port"]
    elif get_instance_count() == 1:
        # Single instance - auto-route
        instance = get_single_instance()
        if instance:
            target_host = instance["host"]
            target_port = instance["port"]
    elif get_instance_count() > 1:
        # Multiple instances - require binary parameter
        request_id = request_obj.get("id")
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "Multiple IDA instances are connected. Please specify the 'binary' parameter to select which one to use. Use list_instances to see available binaries.",
            },
            "id": request_id,
        }
    # If no instances registered, try default port (backward compatibility)

    try:
        # Re-serialize request (binary param removed)
        request_data = json.dumps(request_obj).encode("utf-8")
        response = forward_to_instance(request_data, target_host, target_port)

        # Inject binary param into tools/list response
        if method == "tools/list":
            response = add_binary_param_to_schema(response)

        return response
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None

        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n{full_info}",
                "data": str(e),
            },
            "id": request_id,
        }


mcp.registry.dispatch = dispatch_proxy


# MCP tool: list_instances
@mcp.tool
def list_instances() -> list[dict]:
    """List all connected IDA Pro instances with their binary information"""
    # Always try to discover new instances
    discover_ida_instances(IDA_HOST)

    with _instances_lock:
        return [
            {
                "binary_id": binary_id,
                "module": info.get("module", ""),
                "path": info.get("path", ""),
                "md5": info.get("md5", ""),
                "sha256": info.get("sha256", ""),
                "port": info.get("port", 0),
                "registered_at": info.get("registered_at", 0),
            }
            for binary_id, info in IDA_INSTANCES.items()
        ]


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )


def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config(*, stdio: bool):
    if stdio:
        mcp_config = {
            "command": get_python_executable(),
            "args": [
                __file__,
                "--ida-rpc",
                f"http://{IDA_HOST}:{IDA_PORT}",
            ],
        }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config
    else:
        return {"type": "http", "url": f"http://{IDA_HOST}:{IDA_PORT}/mcp"}


def print_mcp_config():
    print("[HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=False)}}, indent=2
        )
    )
    print("\n[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=True)}}, indent=2
        )
    )


def install_mcp_servers(*, stdio: bool = False, uninstall=False, quiet=False):
    # Map client names to their JSON key paths for clients that don't use "mcpServers"
    # Format: client_name -> (top_level_key, nested_key)
    # None means use default "mcpServers" at top level
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
        "Visual Studio 2022": (None, "servers"),  # servers at top level
    }

    if sys.platform == "win32":
        configs = {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(
                config_path,
                "rb" if is_toml else "r",
                encoding=None if is_toml else "utf-8",
            ) as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)"
                                )
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)"
                                )
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers at top level (e.g., Visual Studio 2022)
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                # Default: mcpServers at top level
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = generate_mcp_config(stdio=stdio)

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(
            dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
        )
        try:
            with os.fdopen(
                fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
            ) as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1
    if not uninstall and installed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")

    # Install both the loader file and package directory
    loader_source = IDA_PLUGIN_LOADER
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")

    pkg_source = IDA_PLUGIN_PKG
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")

    # Clean up old plugin if it exists
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        # Remove loader
        if os.path.lexists(loader_destination):
            os.remove(loader_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin loader\n  Path: {loader_destination}")

        # Remove package
        if os.path.exists(pkg_destination):
            if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                shutil.rmtree(pkg_destination)
            else:
                os.remove(pkg_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin package\n  Path: {pkg_destination}")

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin\n  Path: {old_plugin}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin file\n  Path: {old_plugin}")

        installed_items = []

        # Install loader file
        loader_realpath = (
            os.path.realpath(loader_destination)
            if os.path.lexists(loader_destination)
            else None
        )
        if loader_realpath != loader_source:
            if os.path.lexists(loader_destination):
                os.remove(loader_destination)

            try:
                os.symlink(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")
            except OSError:
                shutil.copy(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")

        # Install package directory
        pkg_realpath = (
            os.path.realpath(pkg_destination)
            if os.path.lexists(pkg_destination)
            else None
        )
        if pkg_realpath != pkg_source:
            if os.path.lexists(pkg_destination):
                if os.path.isdir(pkg_destination) and not os.path.islink(
                    pkg_destination
                ):
                    shutil.rmtree(pkg_destination)
                else:
                    os.remove(pkg_destination)

            try:
                os.symlink(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")
            except OSError:
                shutil.copytree(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")

        if not quiet:
            if installed_items:
                print("Installed IDA Pro plugin (IDA restart required)")
                for item in installed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin installation (already up to date)")


def register_instance(data: dict) -> dict:
    """Register an IDA instance"""
    sha256 = data.get("sha256", "")
    md5 = data.get("md5", "")
    binary_id = sha256 if sha256 else md5

    if not binary_id:
        return {"success": False, "error": "No sha256 or md5 provided"}

    with _instances_lock:
        IDA_INSTANCES[binary_id] = {
            "host": data.get("host", "127.0.0.1"),
            "port": data.get("port", 13337),
            "path": data.get("path", ""),
            "module": data.get("module", ""),
            "md5": md5,
            "sha256": sha256,
            "registered_at": time.time(),
        }

    return {"success": True, "binary_id": binary_id}


def unregister_instance(data: dict) -> dict:
    """Unregister an IDA instance"""
    binary_id = data.get("binary_id", "")
    sha256 = data.get("sha256", "")
    md5 = data.get("md5", "")

    # Try to find by binary_id, sha256, or md5
    key_to_remove = None
    with _instances_lock:
        if binary_id and binary_id in IDA_INSTANCES:
            key_to_remove = binary_id
        elif sha256 and sha256 in IDA_INSTANCES:
            key_to_remove = sha256
        elif md5 and md5 in IDA_INSTANCES:
            key_to_remove = md5

        if key_to_remove:
            del IDA_INSTANCES[key_to_remove]
            return {"success": True, "binary_id": key_to_remove}

    return {"success": False, "error": "Instance not found"}


class RegistryHttpHandler(BaseHTTPRequestHandler):
    """HTTP handler for instance registration endpoints"""

    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_POST(self):
        if self.path == "/register":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                result = register_instance(data)
                self._send_json(result)
            except json.JSONDecodeError:
                self._send_json({"success": False, "error": "Invalid JSON"}, 400)
        elif self.path == "/unregister":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                result = unregister_instance(data)
                self._send_json(result)
            except json.JSONDecodeError:
                self._send_json({"success": False, "error": "Invalid JSON"}, 400)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_GET(self):
        if self.path == "/instances":
            with _instances_lock:
                instances = [
                    {
                        "binary_id": binary_id,
                        "module": info.get("module", ""),
                        "path": info.get("path", ""),
                        "port": info.get("port", 0),
                    }
                    for binary_id, info in IDA_INSTANCES.items()
                ]
            self._send_json({"instances": instances})
        else:
            self._send_json({"error": "Not found"}, 404)

    def _send_json(self, data: dict, status: int = 200):
        response = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def start_registry_server(host: str = "127.0.0.1", port: int = MAIN_SERVER_PORT):
    """Start the registry HTTP server in a background thread"""
    server = HTTPServer((host, port), RegistryHttpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def discover_ida_instances(
    host: str = "127.0.0.1", start_port: int = 13338, max_tries: int = 10
):
    """Discover running IDA instances by scanning ports and querying idb_meta"""
    discovered = 0
    for i in range(max_tries):
        port = start_port + i
        try:
            # Try to call idb_meta on this port
            conn = http.client.HTTPConnection(host, port, timeout=2)
            request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "idb_meta", "arguments": {}},
                "id": 1,
            }
            conn.request(
                "POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"}
            )
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            conn.close()

            # Check if we got valid metadata
            if "result" in data and "content" in data["result"]:
                content = data["result"]["content"]
                if content and len(content) > 0 and "text" in content[0]:
                    metadata = json.loads(content[0]["text"])
                    # Register this instance
                    register_data = {
                        "host": host,
                        "port": port,
                        "path": metadata.get("path", ""),
                        "module": metadata.get("module", ""),
                        "md5": metadata.get("md5", ""),
                        "sha256": metadata.get("sha256", ""),
                    }
                    result = register_instance(register_data)
                    if result.get("success"):
                        discovered += 1
                        # Note: Don't print to stdout in stdio mode - it breaks the protocol
                        print(
                            f"[MCP] Discovered IDA instance: {metadata.get('module', 'unknown')} on port {port}",
                            file=sys.stderr
                        )
        except Exception:
            # Port not responding or not an IDA instance
            pass

    return discovered


def main():
    global IDA_HOST, IDA_PORT
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install", action="store_true", help="Install the MCP Server and IDA plugin"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall the MCP Server and IDA plugin",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=f"http://{IDA_HOST}:{IDA_PORT}",
        help=f"IDA RPC server to use (default: http://{IDA_HOST}:{IDA_PORT})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    args = parser.parse_args()

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers(stdio=(args.transport == "stdio"))
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    # Start the registry HTTP server in background for IDA instances to register
    registry_server = None
    try:
        registry_server = start_registry_server(IDA_HOST, MAIN_SERVER_PORT)
    except OSError as e:
        # Port already in use - another main server is running, that's fine
        if e.errno not in (48, 98, 10048):
            raise

    # Discover already running IDA instances
    discover_ida_instances(IDA_HOST)

    try:
        if args.transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        if registry_server:
            registry_server.shutdown()


if __name__ == "__main__":
    main()
