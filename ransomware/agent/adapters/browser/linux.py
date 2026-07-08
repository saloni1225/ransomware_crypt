"""Linux browser adapter — delegates to shared psutil implementation."""
from adapters.browser.windows import LinuxBrowserAdapter  # re-export
from adapters.registry import register
register("browser", "Linux", LinuxBrowserAdapter)
