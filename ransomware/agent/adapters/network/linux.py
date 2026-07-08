"""Linux network adapter — delegates to shared psutil implementation."""
from adapters.network.windows import LinuxNetworkAdapter  # re-export
from adapters.registry import register
register("network", "Linux", LinuxNetworkAdapter)
