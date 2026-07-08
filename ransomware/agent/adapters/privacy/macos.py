"""macOS privacy adapter — delegates to shared implementation."""
from adapters.privacy.windows import MacOSPrivacyAdapter  # re-export
from adapters.registry import register
register("privacy", "Darwin", MacOSPrivacyAdapter)
