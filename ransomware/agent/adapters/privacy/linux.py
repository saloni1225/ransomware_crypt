"""Linux privacy adapter — delegates to shared implementation."""
from adapters.privacy.windows import LinuxPrivacyAdapter  # re-export
from adapters.registry import register
register("privacy", "Linux", LinuxPrivacyAdapter)
