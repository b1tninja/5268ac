"""Deprecated: use :mod:`boardfs.tl_chain` NTL helpers."""

from boardfs import AssembledNTLResult
from boardfs.tl_chain import assemble_opentla4_ntl_bytes, ntl_result_to_jsonable

__all__ = [
    "AssembledNTLResult",
    "assemble_opentla4_ntl_bytes",
    "ntl_result_to_jsonable",
]
