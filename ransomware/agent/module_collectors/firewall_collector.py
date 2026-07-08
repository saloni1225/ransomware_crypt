"""
Firewall Module Collector
==========================
Periodic thread that reads host firewall status and posts to backend.
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

logger = logging.getLogger("agent.collector.firewall")

_COLLECT_INTERVAL_SEC: int = int(os.getenv("RDS_FIREWALL_POLL", "120"))  # every 2 min


def _post_to_backend(session: requests.Session, payload: dict) -> bool:
    url = f"{config.BACKEND_URL}/firewall/status"
    try:
        r = session.post(url, json=payload, timeout=10)
        return r.status_code in (200, 201)
    except Exception as exc:
        logger.debug("Firewall status POST failed: %s", exc)
    return False


def _collect_loop(stop_event: threading.Event) -> None:
    adapter = get_adapter("firewall")
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

            sender.enqueue("firewall", "telemetry_snapshot", payload)
            _post_to_backend(session, payload)

            logger.debug(
                "Firewall snapshot: supported=%s health=%s",
                result.supported, result.health,
            )
        except Exception as exc:
            logger.error("Firewall collector error: %s", exc)

        stop_event.wait(_COLLECT_INTERVAL_SEC)


def start_firewall_collector() -> tuple:
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_collect_loop,
        args=(stop_event,),
        daemon=True,
        name="agent-firewall-collector",
    )
    thread.start()
    logger.info("Firewall collector started (interval=%ds)", _COLLECT_INTERVAL_SEC)
    return thread, stop_event
