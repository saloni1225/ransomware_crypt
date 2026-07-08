"""
Browser Module Collector
=========================
Periodic thread that scans running browser processes and posts to backend.
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

logger = logging.getLogger("agent.collector.browser")

_COLLECT_INTERVAL_SEC: int = int(os.getenv("RDS_BROWSER_POLL", "60"))  # every 1 min


def _post_to_backend(session: requests.Session, payload: dict) -> bool:
    url = f"{config.BACKEND_URL}/browser/agent-report"
    try:
        r = session.post(url, json=payload, timeout=10)
        return r.status_code in (200, 201)
    except Exception as exc:
        logger.debug("Browser agent-report POST failed: %s", exc)
    return False


def _collect_loop(stop_event: threading.Event) -> None:
    adapter = get_adapter("browser")
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

            # Only enqueue events when suspicious browsers are found
            if result.supported and result.health in ("warning", "critical"):
                sender.enqueue("browser", "suspicious_process", payload)

            _post_to_backend(session, payload)

            browsers = result.data.get("browsers", [])
            logger.debug(
                "Browser snapshot: %d browsers running, health=%s",
                len(browsers), result.health,
            )
        except Exception as exc:
            logger.error("Browser collector error: %s", exc)

        stop_event.wait(_COLLECT_INTERVAL_SEC)


def start_browser_collector() -> tuple:
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_collect_loop,
        args=(stop_event,),
        daemon=True,
        name="agent-browser-collector",
    )
    thread.start()
    logger.info("Browser collector started (interval=%ds)", _COLLECT_INTERVAL_SEC)
    return thread, stop_event
