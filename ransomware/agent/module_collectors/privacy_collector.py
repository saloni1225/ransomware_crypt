"""
Privacy Module Collector
=========================
Periodic scan of monitored directories for secret patterns and risky files.
"""
from __future__ import annotations

import logging
import os
import sys
import threading

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender
from adapters.registry import get_adapter
from adapters.common.normalizer import sanitize_payload

logger = logging.getLogger("agent.collector.privacy")

_COLLECT_INTERVAL_SEC: int = int(os.getenv("RDS_PRIVACY_POLL", "600"))  # every 10 min


def _post_to_backend(session: requests.Session, payload: dict) -> bool:
    url = f"{config.BACKEND_URL}/privacy/agent-report"
    try:
        r = session.post(url, json=payload, timeout=15)
        return r.status_code in (200, 201)
    except Exception as exc:
        logger.debug("Privacy agent-report POST failed: %s", exc)
    return False


def _collect_loop(stop_event: threading.Event) -> None:
    adapter = get_adapter("privacy")
    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "X-Device-ID": config.DEVICE_ID,
    })

    while not stop_event.is_set():
        try:
            result = adapter.collect()
            payload = sanitize_payload(result.to_dict())
            payload["device_id"] = config.DEVICE_ID

            findings = result.data.get("findings", [])

            # Enqueue high-severity findings individually for immediate backend processing
            for finding in findings:
                if finding.get("severity") in ("high", "medium"):
                    sender.enqueue("privacy", "finding", {
                        "device_id": config.DEVICE_ID,
                        "finding_type": finding.get("type"),
                        "path": finding.get("path"),
                        "severity": finding.get("severity"),
                        "reason": finding.get("reason"),
                    })

            _post_to_backend(session, payload)

            logger.debug(
                "Privacy scan: %d findings across %d paths, health=%s",
                len(findings), len(result.data.get("monitored_paths", [])), result.health,
            )
        except Exception as exc:
            logger.error("Privacy collector error: %s", exc)

        stop_event.wait(_COLLECT_INTERVAL_SEC)


def start_privacy_collector() -> tuple:
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_collect_loop,
        args=(stop_event,),
        daemon=True,
        name="agent-privacy-collector",
    )
    thread.start()
    logger.info("Privacy collector started (interval=%ds)", _COLLECT_INTERVAL_SEC)
    return thread, stop_event
