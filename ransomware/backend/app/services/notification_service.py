import requests
from app.config import settings
from app.models import ThreatEvent

def send_threat_notification(event: ThreatEvent):
    if not settings.WEBHOOK_URL:
        print("Webhook notifications: No WEBHOOK_URL configured, skipping.")
        return

    payload = {
        "event_id": event.id,
        "device_id": event.device_id,
        "title": event.title,
        "description": event.description,
        "category": event.category,
        "severity": event.severity,
        "confidence_score": event.confidence_score,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None
    }

    try:
        response = requests.post(settings.WEBHOOK_URL, json=payload, timeout=5)
        response.raise_for_status()
        print(f"Webhook notification sent successfully for event {event.id}.")
    except Exception as e:
        print(f"Failed to send webhook notification for event {event.id}: {e}")
