"""
utils/runtime.py
Runtime settings set once in main() and read by every HTTP module.
Avoids passing proxy/delay through every function signature.
"""

_proxy: str | None = None
_delay: float      = 0.0


def set_proxy(url: str) -> None:
    global _proxy
    _proxy = url


def get_proxies() -> dict | None:
    """Return a requests-compatible proxies dict, or None."""
    if _proxy:
        return {"http": _proxy, "https": _proxy}
    return None


def set_delay(seconds: float) -> None:
    global _delay
    _delay = float(seconds)


def get_delay() -> float:
    return _delay