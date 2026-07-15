"""
BPC MCP Server — exposes BPC pair management as MCP tools for Claude, Cursor, etc.

Tools:
    bpc_list_pairs        List all saved BPC pairs
    bpc_pair_info         Get details for a specific pair
    bpc_register_pair     Register a new pair with a server
    bpc_rotate_pair       Rotate a pair's secret
    bpc_server_status     Check server health and threat score
    bpc_audit_log         Query the server audit log
    bpc_signed_request    Make a BPC-signed HTTP request

Usage (Claude Desktop config):
    {
      "mcpServers": {
        "bpc": {
          "command": "bpc-mcp",
          "env": {}
        }
      }
    }
"""

import json
import sys
import os
from typing import Any

# MCP protocol via stdio
import asyncio


def _json_response(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


TOOLS = [
    {
        "name": "bpc_list_pairs",
        "description": "List all saved BPC pairs on this machine",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "bpc_pair_info",
        "description": "Get details for a specific saved BPC pair",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Pair name"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "bpc_register_pair",
        "description": "Register a new BPC pair with a BPC-protected server",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Server base URL"},
                "name": {"type": "string", "description": "Human-readable pair name"},
                "secret": {"type": "string", "description": "Pair secret (16-128 chars; reference policy applies)"},
                "scope": {
                    "type": "string",
                    "enum": ["read", "read-write", "admin"],
                    "description": "Pair scope",
                    "default": "read-write",
                },
                "mode": {
                    "type": "string",
                    "enum": ["development", "production"],
                    "description": "Pair mode",
                    "default": "development",
                },
            },
            "required": ["base_url", "name", "secret"],
        },
    },
    {
        "name": "bpc_rotate_pair",
        "description": "Rotate the signing key for a saved BPC pair",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Pair name"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "bpc_server_status",
        "description": "Check a BPC server's health and anomaly threat score",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Server base URL"},
                "pair_name": {"type": "string", "description": "Use this pair's saved base URL"},
            },
            "required": [],
        },
    },
    {
        "name": "bpc_audit_log",
        "description": "Query the BPC server audit log (requires admin scope pair)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pair_name": {"type": "string", "description": "Saved pair name (admin scope)"},
                "limit": {"type": "integer", "description": "Max entries to return", "default": 20},
            },
            "required": ["pair_name"],
        },
    },
    {
        "name": "bpc_signed_request",
        "description": "Make a BPC-signed HTTP request using a saved pair",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pair_name": {"type": "string", "description": "Saved pair name"},
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                    "description": "HTTP method",
                },
                "path": {"type": "string", "description": "Request path (e.g. /api/data)"},
                "body": {"type": "object", "description": "Request body (JSON)"},
            },
            "required": ["pair_name", "method", "path"],
        },
    },
]


def handle_tool_call(name: str, arguments: dict) -> str:
    from bpc_client.client import BPCClient, BPCError

    try:
        if name == "bpc_list_pairs":
            pairs = BPCClient._load_pairs_file()
            result = [
                {
                    "name": k,
                    "pair_id": v.get("pair_id"),
                    "scope": v.get("scope"),
                    "base_url": v.get("base_url"),
                }
                for k, v in pairs.items()
            ]
            return _json_response(result)

        elif name == "bpc_pair_info":
            pairs = BPCClient._load_pairs_file()
            pair_name = arguments["name"]
            if pair_name not in pairs:
                return json.dumps({"error": f"No pair named '{pair_name}'"})
            data = {k: v for k, v in pairs[pair_name].items() if k != "private_key_pem"}
            return _json_response(data)

        elif name == "bpc_register_pair":
            client = BPCClient.register(
                base_url=arguments["base_url"],
                name=arguments["name"],
                secret=arguments["secret"],
                scope=arguments.get("scope", "read-write"),
                mode=arguments.get("mode", "development"),
            )
            return _json_response({
                "ok": True,
                "pair_id": client.pair_id,
                "name": arguments["name"],
                "message": "Pair registered and saved successfully",
            })

        elif name == "bpc_rotate_pair":
            client = BPCClient.load(name=arguments["name"])
            new_client = client.rotate()
            return _json_response({"ok": True, "pair_id": new_client.pair_id})

        elif name == "bpc_server_status":
            import httpx
            base_url = arguments.get("base_url")
            if not base_url and arguments.get("pair_name"):
                pairs = BPCClient._load_pairs_file()
                base_url = pairs.get(arguments["pair_name"], {}).get("base_url")
            if not base_url:
                return json.dumps({"error": "Provide base_url or pair_name"})
            r = httpx.get(f"{base_url.rstrip('/')}/bpc/health", timeout=10)
            return _json_response(r.json())

        elif name == "bpc_audit_log":
            client = BPCClient.load(name=arguments["pair_name"])
            limit = arguments.get("limit", 20)
            resp = client.get(f"/bpc/audit?limit={limit}")
            return _json_response(resp.json())

        elif name == "bpc_signed_request":
            client = BPCClient.load(name=arguments["pair_name"])
            kwargs = {}
            if "body" in arguments:
                kwargs["json"] = arguments["body"]
            resp = client.request(arguments["method"], arguments["path"], **kwargs)
            try:
                return _json_response({"status": resp.status_code, "body": resp.json()})
            except Exception:
                return json.dumps({"status": resp.status_code, "body": resp.text})

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})

    except BPCError as e:
        return json.dumps({"error": str(e), "code": e.code})
    except Exception as e:
        return json.dumps({"error": str(e)})


async def run_mcp_server():
    """Run the MCP server over stdio."""
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    _, writer = await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout)

    async def send(msg: dict):
        line = json.dumps(msg) + "\n"
        sys.stdout.write(line)
        sys.stdout.flush()

    while True:
        try:
            line = await reader.readline()
            if not line:
                break
            msg = json.loads(line.decode())
        except Exception:
            break

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "initialize":
            await send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "bpc-mcp", "version": "1.0.0"},
                },
            })

        elif method == "tools/list":
            await send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS},
            })

        elif method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            content = handle_tool_call(tool_name, arguments)
            await send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": content}],
                    "isError": False,
                },
            })

        elif method == "notifications/initialized":
            pass  # no response needed

        else:
            if msg_id is not None:
                await send({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                })


def main():
    asyncio.run(run_mcp_server())


if __name__ == "__main__":
    main()
