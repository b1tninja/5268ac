"""CLI: ``python -m lib2spy.pkgstream_runtime`` — TLV prefix dry-run (JSON or ``--text``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lib2spy.pkgstream_runtime.tlv_dry_run import trace_pkgstream_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m lib2spy.pkgstream_runtime",
        description=(
            "Dry-run: walk prefix TLVs (iter_tlvs_prefix_only) with install_action hints from "
            "INSTALL_TLV_DEMARSHALL. No mount, no full lib2sp FSM."
        ),
    )
    p.add_argument("pkgstream", type=str, help="Path to a .pkgstream carrier")
    p.add_argument(
        "--text",
        action="store_true",
        help="Print a text table instead of JSON",
    )
    args = p.parse_args(argv)

    path = Path(args.pkgstream)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 1

    report = trace_pkgstream_path(path)
    if args.text:
        h = report["header"]
        print(f"path: {report['path']}")
        print(f"raw_size={report['raw_size']} body_size={report['body_size']} outer_bzip2={report['outer_bzip2']}")
        print(f"header.magic={h['magic']!r} supported={h['is_supported_magic']} u32={h['u32']}")
        print(f"TLV prefix ({len(report['tlv_trace'])} records)")
        for row in report["tlv_trace"]:
            extra = ""
            if "install_hint" in row:
                ih = row["install_hint"]
                act = ih.get("install_action") or ""
                com = (ih.get("install_comment") or "").replace("\n", " ")
                if len(com) > 52:
                    com = com[:49] + "..."
                extra = f"  [{act}]  # {com}" if com else f"  [{act}]"
            print(
                f"  {row['index']:>3}  {row['type']:>6}  {row['name']:<14}  "
                f"off={row['offset']:<8}  len={row['length']:<8}{extra}"
            )
    else:
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
