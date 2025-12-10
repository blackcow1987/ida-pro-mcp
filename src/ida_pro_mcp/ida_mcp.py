"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import json
import http.client
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


MAIN_SERVER_HOST = "127.0.0.1"
MAIN_SERVER_PORT = 13337


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def register_with_main_server(host: str, port: int, metadata: dict) -> bool:
    """Register this IDA instance with the main MCP server"""
    try:
        data = {
            "host": host,
            "port": port,
            "path": metadata.get("path", ""),
            "module": metadata.get("module", ""),
            "md5": metadata.get("md5", ""),
            "sha256": metadata.get("sha256", ""),
        }
        conn = http.client.HTTPConnection(MAIN_SERVER_HOST, MAIN_SERVER_PORT, timeout=5)
        conn.request("POST", "/register", json.dumps(data), {"Content-Type": "application/json"})
        response = conn.getresponse()
        result = json.loads(response.read().decode())
        conn.close()
        return result.get("success", False)
    except Exception as e:
        print(f"[MCP] Warning: Failed to register with main server: {e}")
        return False


def unregister_from_main_server(metadata: dict) -> bool:
    """Unregister this IDA instance from the main MCP server"""
    try:
        data = {
            "sha256": metadata.get("sha256", ""),
            "md5": metadata.get("md5", ""),
        }
        conn = http.client.HTTPConnection(MAIN_SERVER_HOST, MAIN_SERVER_PORT, timeout=5)
        conn.request("POST", "/unregister", json.dumps(data), {"Content-Type": "application/json"})
        response = conn.getresponse()
        result = json.loads(response.read().decode())
        conn.close()
        return result.get("success", False)
    except Exception:
        return False


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # TODO: make these configurable
    HOST = "127.0.0.1"
    BASE_PORT = 13338  # Start from 13338 (13337 is reserved for main server)
    MAX_PORT_TRIES = 10

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self._current_port: int = 0
        self._metadata: dict = {}
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            # Unregister before stopping
            if self._metadata:
                unregister_from_main_server(self._metadata)
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
            from .ida_mcp.api_core import idb_meta
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
            from ida_mcp.api_core import idb_meta

        for i in range(self.MAX_PORT_TRIES):
            port = self.BASE_PORT + i
            try:
                MCP_SERVER.serve(
                    self.HOST, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.HOST}:{port}/config.html")
                self.mcp = MCP_SERVER
                self._current_port = port

                # Get metadata and register with main server
                self._metadata = idb_meta()
                if register_with_main_server(self.HOST, port, self._metadata):
                    print(f"[MCP] Registered with main server (binary: {self._metadata.get('module', 'unknown')})")
                break
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    if i == self.MAX_PORT_TRIES - 1:
                        print(
                            f"[MCP] Error: Could not find available port in range {self.BASE_PORT}-{self.BASE_PORT + self.MAX_PORT_TRIES - 1}"
                        )
                        return
                    continue
                raise

    def term(self):
        if self.mcp:
            # Unregister before stopping
            if self._metadata:
                unregister_from_main_server(self._metadata)
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
