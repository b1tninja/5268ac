"""
Kernel ``bootargs`` string parsing (Linux command line).

Embedded cmdlines are usually **space-separated** ``key=value`` tokens. This module does
not implement the full kernel parser (no initrd memory ranges, no quoted merging); it is
sufficient for extracting ``mtdparts=`` and other keys from dumps / ``/proc/cmdline`` style
strings.
"""

from __future__ import annotations

import re
from typing import Mapping

# Token that carries mtdparts (space-delimited in bootargs).
_MTDPARTS_TOKEN = re.compile(r"^mtdparts=", re.IGNORECASE)


#region kernel_adjacent bootargs_mtdparts_subset (intentional subset of kernel cmdline parsing)
def parse_bootargs(cmdline: str) -> dict[str, str | None]:
    """
    Split ``cmdline`` into a mapping of keys to values.

    * ``name=value`` → ``{"name": "value"}`` (first ``=`` splits key from value).
    * ``name`` (no ``=``) → ``{"name": None}``.
    * Duplicate keys: last occurrence wins (matches common /proc/cmdline behavior).
    """
    out: dict[str, str | None] = {}
    for raw in cmdline.split():
        tok = raw.strip()
        if not tok:
            continue
        if "=" in tok:
            k, _, v = tok.partition("=")
            out[k] = v
        else:
            out[tok] = None
    return out


def get_mtdparts_token(cmdline: str) -> str | None:
    """
    Return the **single space-delimited token** that starts with ``mtdparts=``, if any.

    Important: :func:`unand.mtd.parse_mtdparts` uses a regex that would otherwise greedily
    consume text after the partition list if the full ``bootargs`` string is passed in one
    blob. Always pass only this token (or a string that ends at the partition list) when
    chaining into ``unand.mtd``.
    """
    for raw in cmdline.split():
        tok = raw.strip()
        if _MTDPARTS_TOKEN.match(tok):
            return tok
    return None


def env_blob_to_cmdline_like_string(blob: bytes) -> str:
    """
    Decode a raw U-Boot **env** slice: ``k=v`` pairs are often **NUL-separated**.

    Replace NUL with ASCII space so :func:`get_mtdparts_token` / :func:`parse_bootargs` see
    space-delimited tokens like a Linux cmdline.
    """
    return blob.replace(b"\x00", b" ").decode("ascii", errors="replace")


def get_mtdparts_token_from_env_blob(blob: bytes) -> str | None:
    """Extract the ``mtdparts=…`` token from a raw env blob (NUL-separated pairs)."""
    return get_mtdparts_token(env_blob_to_cmdline_like_string(blob))


def bootargs_mapping(cmdline: str) -> Mapping[str, str | None]:
    """Alias for :func:`parse_bootargs` (read-only view type)."""
    return parse_bootargs(cmdline)


#endregion
