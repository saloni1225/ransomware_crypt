"""macOS browser adapter — delegates to shared psutil implementation."""
from adapters.browser.windows import MacOSBrowserAdapter  # re-export
from adapters.registry import register
register("browser", "Darwin", MacOSBrowserAdapter)
