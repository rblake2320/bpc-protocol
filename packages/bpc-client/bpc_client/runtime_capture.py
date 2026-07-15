"""Opt-in AI runtime metadata capture for BPC Python key generation."""

from __future__ import annotations

import datetime as _dt
import os
import sys
from collections.abc import Callable
from typing import Any

AIRuntimeMetadata = dict[str, Any]
KeyGenerationCaptureEvent = dict[str, Any]
KeyGenerationCaptureSink = Callable[[KeyGenerationCaptureEvent], None]

REDACTED = "[REDACTED]"
_capture_sink: KeyGenerationCaptureSink | None = None
_SENSITIVE_PARTS = (
    "secret",
    "token",
    "password",
    "private",
    "credential",
    "api_key",
    "apikey",
    "shared_secret",
    "raw_key",
    "authorization",
)


def set_key_generation_capture_sink(sink: KeyGenerationCaptureSink | None) -> None:
    """Install or clear the process-local capture sink."""
    global _capture_sink
    _capture_sink = sink


def collect_runtime_metadata(overrides: AIRuntimeMetadata | None = None) -> AIRuntimeMetadata:
    """Collect Claude/Codex-style runtime metadata from env plus explicit overrides."""
    env = os.environ
    metadata: AIRuntimeMetadata = {
        "capturedAt": _now_iso(),
        "source": "env",
        "tool": _first_env(env, "AI_RUNTIME_TOOL", "CODEX_RUNTIME_TOOL", "CLAUDE_RUNTIME_TOOL"),
        "toolVersion": _first_env(env, "AI_RUNTIME_TOOL_VERSION", "CODEX_VERSION", "CLAUDE_CODE_VERSION")
        or sys.version.split()[0],
        "model": _first_env(env, "AI_RUNTIME_MODEL", "CODEX_MODEL", "CLAUDE_MODEL", "ANTHROPIC_MODEL"),
        "reasoning": _first_env(env, "AI_RUNTIME_REASONING", "CODEX_REASONING", "CLAUDE_REASONING"),
        "summaryMode": _first_env(env, "AI_RUNTIME_SUMMARY_MODE", "CODEX_SUMMARY_MODE", "CLAUDE_SUMMARY_MODE"),
        "directory": _first_env(env, "AI_RUNTIME_DIRECTORY", "AI_RUNTIME_CWD", "CODEX_CWD", "CLAUDE_PROJECT_DIR"),
        "cwd": _first_env(env, "AI_RUNTIME_CWD", "CODEX_CWD", "CLAUDE_PROJECT_DIR") or os.getcwd(),
        "permissions": _first_env(env, "AI_RUNTIME_PERMISSIONS", "CODEX_PERMISSIONS", "CLAUDE_PERMISSIONS"),
        "agentsMd": _first_env(env, "AI_RUNTIME_AGENTS_MD", "CODEX_AGENTS_MD", "CLAUDE_AGENTS_MD"),
        "account": _first_env(env, "AI_RUNTIME_ACCOUNT", "CODEX_ACCOUNT", "CLAUDE_ACCOUNT"),
        "email": _first_env(env, "AI_RUNTIME_EMAIL", "CODEX_EMAIL", "CLAUDE_EMAIL"),
        "organization": _first_env(env, "AI_RUNTIME_ORGANIZATION", "CODEX_ORGANIZATION", "CLAUDE_ORGANIZATION"),
        "loginMethod": _first_env(env, "AI_RUNTIME_LOGIN_METHOD", "CODEX_LOGIN_METHOD", "CLAUDE_LOGIN_METHOD"),
        "collaborationMode": _first_env(
            env, "AI_RUNTIME_COLLABORATION_MODE", "CODEX_COLLABORATION_MODE", "CLAUDE_COLLABORATION_MODE"
        ),
        "sessionId": _first_env(env, "AI_RUNTIME_SESSION_ID", "CODEX_SESSION_ID", "CLAUDE_SESSION_ID"),
        "sessionName": _first_env(env, "AI_RUNTIME_SESSION_NAME", "CODEX_SESSION_NAME", "CLAUDE_SESSION_NAME"),
        "contextWindow": _first_env(env, "AI_RUNTIME_CONTEXT_WINDOW", "CODEX_CONTEXT_WINDOW", "CLAUDE_CONTEXT_WINDOW"),
        "contextUsed": _first_env(env, "AI_RUNTIME_CONTEXT_USED", "CODEX_CONTEXT_USED", "CLAUDE_CONTEXT_USED"),
        "contextLeft": _first_env(env, "AI_RUNTIME_CONTEXT_LEFT", "CODEX_CONTEXT_LEFT", "CLAUDE_CONTEXT_LEFT"),
        "limits": _first_env(env, "AI_RUNTIME_LIMITS", "CODEX_LIMITS", "CLAUDE_LIMITS"),
        "mcpServers": _first_env(env, "AI_RUNTIME_MCP_SERVERS", "CODEX_MCP_SERVERS", "CLAUDE_MCP_SERVERS"),
        "settingSources": _first_env(
            env, "AI_RUNTIME_SETTING_SOURCES", "CODEX_SETTING_SOURCES", "CLAUDE_SETTING_SOURCES"
        ),
        "statusText": _first_env(env, "AI_RUNTIME_STATUS_TEXT", "CODEX_STATUS_TEXT", "CLAUDE_STATUS_TEXT"),
        "configText": _first_env(env, "AI_RUNTIME_CONFIG_TEXT", "CODEX_CONFIG_TEXT", "CLAUDE_CONFIG_TEXT"),
        "usageText": _first_env(env, "AI_RUNTIME_USAGE_TEXT", "CODEX_USAGE_TEXT", "CLAUDE_USAGE_TEXT"),
        "statsText": _first_env(env, "AI_RUNTIME_STATS_TEXT", "CODEX_STATS_TEXT", "CLAUDE_STATS_TEXT"),
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}
    if overrides:
        metadata.update(overrides)
        metadata["source"] = "combined"
    return sanitize_capture_value(metadata)


def emit_key_generation_capture(event: KeyGenerationCaptureEvent) -> None:
    """Emit a sanitized capture event if a sink is installed."""
    if _capture_sink is None:
        return
    safe_event = sanitize_capture_value(
        {
            **event,
            "generatedAt": event.get("generatedAt") or _now_iso(),
            "runtime": collect_runtime_metadata(event.get("runtime") or {}),
        }
    )
    try:
        _capture_sink(safe_event)
    except Exception:
        pass


def sanitize_capture_value(value: Any, field_name: str = "") -> Any:
    if _is_sensitive_field(field_name):
        return REDACTED
    if isinstance(value, dict):
        return {key: sanitize_capture_value(nested, str(key)) for key, nested in value.items()}
    if isinstance(value, list):
        return [sanitize_capture_value(item) for item in value]
    return value


def _first_env(env: os._Environ[str], *names: str) -> str | None:
    for name in names:
        value = env.get(name)
        if value and value.strip():
            return value
    return None


def _is_sensitive_field(field_name: str) -> bool:
    normalized = field_name.replace("-", "_").replace(" ", "_").lower()
    compact = normalized.replace("_", "")
    return any(part in normalized or part.replace("_", "") in compact for part in _SENSITIVE_PARTS)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z")
