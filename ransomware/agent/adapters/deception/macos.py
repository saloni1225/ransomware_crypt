"""macOS deception adapter — delegates to shared implementation."""
from adapters.deception.windows import MacOSDeceptionAdapter
from adapters.registry import register
register("deception", "Darwin", MacOSDeceptionAdapter)
