"""Linux deception adapter — delegates to shared implementation."""
from adapters.deception.windows import LinuxDeceptionAdapter
from adapters.registry import register
register("deception", "Linux", LinuxDeceptionAdapter)
