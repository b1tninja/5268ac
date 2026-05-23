"""Configure :mod:`opentl` logging from environment (no handlers attached here)."""

from __future__ import annotations

import logging
import os

_LOG = logging.getLogger(__name__)


def apply_opentl_log_level_from_env() -> bool:
    """
    Set the ``opentl`` package logger level from ``OPENTL_DEBUG`` or ``OPENTL_LOG_LEVEL``.

    Returns ``True`` when **DEBUG** was explicitly selected (``OPENTL_DEBUG`` non-empty or
    ``OPENTL_LOG_LEVEL=DEBUG``), so callers can attach stderr logging if desired.

    Does not add handlers — only adjusts :meth:`logging.Logger.setLevel` on ``"opentl"``.
    """
    log = logging.getLogger("opentl")
    if os.environ.get("OPENTL_DEBUG", "").strip():
        log.setLevel(logging.DEBUG)
        return True
    raw = os.environ.get("OPENTL_LOG_LEVEL", "").strip().upper()
    if not raw:
        return False
    level = getattr(logging, raw, None)
    if not isinstance(level, int):
        _LOG.warning("OPENTL_LOG_LEVEL=%r is not a valid logging level name", raw)
        return False
    log.setLevel(level)
    return level <= logging.DEBUG


def configure_opentl_stderr_logging() -> None:
    """
    Apply env level to ``opentl``, then ensure DEBUG messages reach stderr when DEBUG was requested.

    Intended for CLIs (e.g. :mod:`paceflash`). If the root logger already has handlers, lowers
    the root logger's level to DEBUG so child ``opentl.*`` DEBUG records propagate; otherwise
    calls :func:`logging.basicConfig`.
    """
    want = apply_opentl_log_level_from_env()
    if not want:
        return
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s %(name)s: %(message)s",
        )
    else:
        root.setLevel(logging.DEBUG)
