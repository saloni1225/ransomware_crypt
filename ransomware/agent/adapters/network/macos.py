"""macOS network adapter — delegates to shared psutil implementation."""
from adapters.network.windows import MacOSNetworkAdapter  # re-export
from adapters.registry import register
register("network", "Darwin", MacOSNetworkAdapter)
