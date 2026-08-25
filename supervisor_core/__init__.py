"""Agent Supervisor v3 shared core."""

from .constants import EXIT_BLOCKED, EXIT_COMPLETE, EXIT_DEGRADED, EXIT_INCOMPLETE, EXIT_INVALID

__version__ = "3.1.6"

__all__ = [
    "EXIT_COMPLETE",
    "EXIT_INCOMPLETE",
    "EXIT_BLOCKED",
    "EXIT_DEGRADED",
    "EXIT_INVALID",
]
