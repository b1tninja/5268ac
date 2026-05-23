"""
``unand`` — clean-room NAND **dump** reader for 5268-class Pace captures.

Maps raw TSOP images (inline 2048+64 or flat-tail) to the **128 MiB** logical **MTD data
plane** and optionally a **4 MiB** flat spare stream (OOB rows in page order).

**Concepts** (MTD vs spare, page vs OpenTL sector, what spare may hold): see ``README.md``
in this package. **cmdline ``mtdparts=``** slices apply only to the data plane; spare is
not an MTD partition. **OpenTL / ``ntl_*``** spare decoding lives in :mod:`opentl.spare_chain_replay` and sibling modules at the :mod:`opentl` package top level.

**Ghidra ↔ Python:** kernel-analogue code uses ``#region kernel: 0x…`` comments keyed to MIPS EAs; see ``reference/kernel_python_regions.md`` at the repo root.
"""

from __future__ import annotations

__version__ = "0.1.0"

# --- Chip identity ---
from .chip import NandChip

# --- Geometry ---
from .geometry import FLASH_ID_PACE, NandGeometry, PACE_DEFAULT

# --- Layout ---
from .layout import (
    LayoutDetectionError,
    RawDumpLayout,
    detect_layout,
    detect_layout_file,
    read_logical_plane_interval,
)

# --- I/O normalize ---
from .io import extract_spare_bytes, extract_spare_to_file, normalize_to_logical, sha256_logical_plane

# --- MTD cmdline ---
from .mtd import DEFAULT_MTDPARTS, MtdPart, parse_mtdparts, part_by_name

# --- LogicalPlane (file-based) ---
from .plane import LogicalPlane

# --- Programmatic reader ---
from .reader import NANDReader

# --- Hexdump ---
from .hexdump import hexdump

# --- Lazy virtual plane ---
from .vplane import VirtualPlane

# --- S34ML chip family ---
from .s34ml import (
    S34ML,
    S34ML01G1,
    S34ML02G1,
    S34ML04G1,
    S34MLFamily,
    SR1_ECC_UNCOR,
    SR1_ERASE_FAIL,
    SR1_PROGRAM_FAIL,
    SR2_BAD_BLOCK,
    SR2_PROTECTION_FAIL,
    SR2_WRITE_FAIL,
)

__all__ = [
    "__version__",
    # Chip identity
    "NandChip",
    # Geometry
    "FLASH_ID_PACE",
    "NandGeometry",
    "PACE_DEFAULT",
    # Layout
    "RawDumpLayout",
    "LayoutDetectionError",
    "detect_layout",
    "detect_layout_file",
    "read_logical_plane_interval",
    # I/O
    "extract_spare_bytes",
    "extract_spare_to_file",
    "normalize_to_logical",
    "sha256_logical_plane",
    # MTD
    "DEFAULT_MTDPARTS",
    "MtdPart",
    "parse_mtdparts",
    "part_by_name",
    # LogicalPlane
    "LogicalPlane",
    # Programmatic reader
    "NANDReader",
    # Hexdump
    "hexdump",
    # Lazy virtual plane
    "VirtualPlane",
    # S34ML chip family
    "S34ML",
    "S34MLFamily",
    "S34ML01G1",
    "S34ML02G1",
    "S34ML04G1",
    # EDC / Status Register bitmasks
    "SR1_ECC_UNCOR",
    "SR1_ERASE_FAIL",
    "SR1_PROGRAM_FAIL",
    "SR2_BAD_BLOCK",
    "SR2_PROTECTION_FAIL",
    "SR2_WRITE_FAIL",
]
