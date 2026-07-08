"""
Payload Normalizer & Serializer
================================
Shared utilities for sanitizing and serializing adapter payloads
before they are sent to the backend or written to the offline buffer.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict

# Patterns that look like secrets — redact the value but keep the key name
_SECRET_PATTERNS = [
    re.compile(r"(AKIA[0-9A-Z]{16})", re.I),            # AWS access key
    re.compile(r"(sk_[0-9a-zA-Z_]{24,})", re.I),        # Stripe secret
    re.compile(r"(ghp_[0-9a-zA-Z]{36})", re.I),         # GitHub PAT
    re.compile(r"(-----BEGIN [A-Z ]+PRIVATE KEY-----)", re.I),  # PEM header
    re.compile(r"(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})", re.I),  # SendGrid
]


def redact_sensitive(value: str) -> str:
    """Replace recognizable secret patterns with [REDACTED]."""
    for pat in _SECRET_PATTERNS:
        value = pat.sub("[REDACTED]", value)
    return value


def sanitize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively walk a dict and redact any string values that look like secrets.
    Keys themselves are never altered.
    """
    cleaned: Dict[str, Any] = {}
    for k, v in payload.items():
        if isinstance(v, str):
            cleaned[k] = redact_sensitive(v)
        elif isinstance(v, dict):
            cleaned[k] = sanitize_payload(v)
        elif isinstance(v, list):
            cleaned[k] = [
                sanitize_payload(item) if isinstance(item, dict)
                else (redact_sensitive(item) if isinstance(item, str) else item)
                for item in v
            ]
        else:
            cleaned[k] = v
    return cleaned


def serialize(payload: Dict[str, Any]) -> str:
    """JSON-serialize a payload, sanitizing sensitive values first."""
    return json.dumps(sanitize_payload(payload), default=str)


def to_sender_event(normalized_payload) -> Dict[str, Any]:
    """
    Convert a NormalizedPayload into the flat dict format expected by
    AgentSender.enqueue(type, action, details).

    Returns: (log_type, action, details)
    """
    d = normalized_payload.to_dict()
    log_type = d["module"]
    action = "telemetry_snapshot"
    details = sanitize_payload(d)
    return log_type, action, details
