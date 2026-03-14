"""
Shared abort flag for graceful Ctrl+C handling across all modules.
Place this file in the utils/ directory: utils/abort_flag.py

Usage in any module:
    from utils import abort_flag
    if abort_flag.is_set(): ...
"""
import threading

_event = threading.Event()


def set():
    """Signal all modules to stop."""
    _event.set()


def is_set():
    """Returns True if Ctrl+C has been pressed."""
    return _event.is_set()