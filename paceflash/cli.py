"""``python -m paceflash`` — ext2 ``ls`` / ``cat`` on opentla4, plus inventory when ``--debug``."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import textwrap
from pathlib import Path

from typing import Any

from boardfs import configure_opentl_stderr_logging
from boardfs.ext2_path import (
    Ext2DirectoryOpaqueError,
    list_ext2_directory,
    normalize_ext2_path,
    read_ext2_regular_file,
)

from paceflash.board_param import dump_paramtool
from paceflash.eapol_cert import dump_eapol_cert
from paceflash.factory_params import dump_factory_params
from paceflash.http_auth import dump_http_auth
from paceflash.flash_session import open_opentla4_ext2
from paceflash.inventory import build_inventory
from paceflash.shell import Ext2ShellSession, ShellConfig, run_interactive, run_script
from paceflash.upgrade_correlation import build_carrier_index

_DEFAULT_CARRIER_INDEX = Path("output/firmware_00d09e_carrier_index.json")


@contextlib.contextmanager
def _tl_disk_probe_report_env(enabled: bool):
    if not enabled:
        yield
        return
    prev = os.environ.get("OPENTL_TLDISK_REPORT")
    os.environ["OPENTL_TLDISK_REPORT"] = "1"
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("OPENTL_TLDISK_REPORT", None)
        else:
            os.environ["OPENTL_TLDISK_REPORT"] = prev


def _resolve_carrier_index_arg(
    firmware_collection: Path | None,
    carrier_index: Path | None,
) -> Path | None:
    if carrier_index is not None:
        return carrier_index
    if firmware_collection is None:
        return None
    if _DEFAULT_CARRIER_INDEX.is_file():
        return _DEFAULT_CARRIER_INDEX
    return None


def _emit_warnings(warnings: list[str]) -> None:
    for w in warnings:
        print(f"paceflash: warning: {w}", file=sys.stderr)


def _resolve_flash_path(args: argparse.Namespace) -> Path:
    flash, _path = _resolve_flash_and_path_operands(args, require_path=False)
    return flash


def _resolve_flash_and_path_operands(
    args: argparse.Namespace,
    *,
    require_path: bool,
) -> tuple[Path, str]:
    """
    Positionals are a single ``operands`` list so ``--flash`` before the subcommand works:

    - ``paceflash --flash DUMP ls [PATH]`` — operands are only ext2 PATH (0 → ``/``)
    - ``paceflash ls DUMP [PATH]`` — first operand is DUMP, second optional PATH
    """
    ops = [str(p) for p in (getattr(args, "operands", None) or [])]
    flash_opt = getattr(args, "flash_opt", None)

    if flash_opt is not None:
        flash = Path(flash_opt).expanduser().resolve()
        if len(ops) > 1:
            raise SystemExit(
                "paceflash: too many positional arguments (expected at most one ext2 PATH)"
            )
        ext2_path = normalize_ext2_path(ops[0] if ops else "/")
        return flash, ext2_path

    if not ops:
        raise SystemExit("paceflash: flash dump path required (positional FLASH or --flash PATH)")
    if len(ops) == 1:
        if require_path:
            raise SystemExit(
                "paceflash: cat requires PATH (e.g. paceflash cat FLASH sys1/rootimage.img)"
            )
        return Path(ops[0]).expanduser().resolve(), "/"
    if len(ops) == 2:
        return Path(ops[0]).expanduser().resolve(), normalize_ext2_path(ops[1])
    raise SystemExit(
        "paceflash: too many positional arguments "
        "(expected FLASH [PATH] or --flash DUMP plus optional PATH)"
    )


def _cmdline_from_args(args: argparse.Namespace) -> str | None:
    return getattr(args, "cmdline", None)


def _add_nand_args(ap: argparse.ArgumentParser) -> None:
    nand_grp = ap.add_mutually_exclusive_group()
    nand_grp.add_argument(
        "--nand-translate",
        action="store_true",
        help="Logicalize full-chip Pace physical dumps before TL/ext2 (default)",
    )
    nand_grp.add_argument(
        "--no-nand-translate",
        action="store_true",
        help="Skip in-memory NAND logicalize (raw packed image only)",
    )
    ap.add_argument(
        "--nand-mode",
        choices=("inline-2112", "flat-tail", "identity"),
        default="inline-2112",
        help="NAND translate mode for full-chip physical dumps (default inline-2112)",
    )
    ap.add_argument(
        "--bbm-chain-aware",
        action="store_true",
        help="Force spare-chain BBM virtual scan after NAND translate",
    )


def _add_global_flash_options(
    ap: argparse.ArgumentParser,
    *,
    suppress_if_unset: bool = False,
) -> None:
    """``--flash`` / ``--cmdline`` before or after the subcommand (``paceflash --flash X ls``)."""
    unset = argparse.SUPPRESS if suppress_if_unset else None
    ap.add_argument(
        "--flash",
        type=Path,
        dest="flash_opt",
        default=unset,
        metavar="PATH",
        help="Flash dump path (alternative to positional FLASH on ls/cat)",
    )
    ap.add_argument(
        "--cmdline",
        type=str,
        default=unset,
        help="Kernel cmdline with mtdparts= (default: quiet rw + unand.mtd.DEFAULT_MTDPARTS)",
    )


def _add_subcommand_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--tl-slice",
        type=str,
        default="opentla4",
        metavar="NAME",
        help="TL slice holding ext2 (default opentla4)",
    )
    _add_nand_args(ap)


def _add_operands_arg(
    ap: argparse.ArgumentParser,
    *,
    metavar: str,
    help_text: str,
) -> None:
    ap.add_argument("operands", nargs="*", metavar=metavar, help=help_text)


def _print_path_ls(rows: list[dict[str, Any]], *, long_fmt: bool = False) -> None:
    for row in rows:
        if long_fmt:
            print(f"{row.get('file_type', '?'):>10}  {row.get('name', '')}")
        else:
            print(row.get("name", ""))


def _run_ls_path(args: argparse.Namespace, flash_path: Path, *, ext2_path: str = "/") -> int:
    rel = ext2_path
    try:
        with open_opentla4_ext2(
            flash_path,
            _cmdline_from_args(args),
            slice_name=args.tl_slice,
            nand_translate=not args.no_nand_translate,
            nand_translate_mode=args.nand_mode,
            bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
        ) as vol:
            rows = list_ext2_directory(
                vol.slice_bytes,
                rel,
                sb_off=vol.sb_off,
                include_dot=getattr(args, "all", False),
                access=vol.access,
                cmdb_recover=getattr(args, "cmdb_recover", False),
            )
            read_model = vol.read_model
            slice_name = vol.slice_name
    except NotADirectoryError as e:
        print(f"paceflash: not a directory: {e}", file=sys.stderr)
        return 1
    except Ext2DirectoryOpaqueError as e:
        print(f"paceflash: {e}", file=sys.stderr)
        return 1
    except (FileNotFoundError, OSError) as e:
        print(f"paceflash: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"paceflash: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "flash_path": str(flash_path),
                    "slice": slice_name,
                    "path": "/" + rel if rel else "/",
                    "read_model": read_model,
                    "entries": rows,
                },
                indent=2,
            )
        )
    else:
        _print_path_ls(rows, long_fmt=getattr(args, "long", False))
    return 0


def _run_shell(args: argparse.Namespace, flash_path: Path) -> int:
    config = ShellConfig(
        flash_path=flash_path,
        cmdline=_cmdline_from_args(args),
        tl_slice=args.tl_slice,
        nand_translate=not args.no_nand_translate,
        nand_translate_mode=args.nand_mode,
        bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
    )
    print("paceflash: loading flash (NAND translate + ext2 mount)…", file=sys.stderr)
    try:
        session = Ext2ShellSession.open(config)
    except RuntimeError as e:
        print(f"paceflash: {e}", file=sys.stderr)
        return 1

    if getattr(args, "shell_command", None):
        try:
            return session.run_line(args.shell_command)
        except SystemExit:
            return 0

    if not sys.stdin.isatty():
        return run_script(session, sys.stdin.readlines())
    return run_interactive(session)


def _warn_binary_cat_to_tty(data: bytes) -> None:
    """Binary CMDB blobs can contain ESC/C1 bytes that confuse terminal emulators."""
    if not sys.stdout.isatty():
        return
    head = data[:65536]
    esc = head.count(0x1B)
    if esc < 32:
        return
    print(
        f"paceflash: warning: first {len(head)} bytes contain {esc} ESC (0x1B) bytes; "
        "dumping to this terminal may garble the display (cursor/UTF-8 state) even when "
        "later XML is valid — use -o FILE or inspect with a hex editor; run `reset` if "
        "the prompt breaks.",
        file=sys.stderr,
    )


def _warn_cmdb_stride_corruption(data: bytes, rel: str) -> None:
    """
    CMDB XML field names use ASCII ``_`` (0x5f). 0xe8 in names is NAND 512 B/page
    stride corruption (CP1252 consoles often render that byte as ``è``), not UTF-8 text.
    """
    if not rel.replace("\\", "/").startswith(("cm/", "config/")):
        return
    if b"join\xe8notify" in data or b"rx\xe8ifname" in data:
        print(
            "paceflash: warning: CMDB XML has 0xE8 where underscores (0x5F) are expected "
            "(often shown as 'è' in Windows consoles) — extent read is still corrupted. "
            "Save bytes with --output FILE and verify, or update boardfs/paceflash.",
            file=sys.stderr,
        )


def _run_cat(args: argparse.Namespace, flash_path: Path) -> int:
    rel = normalize_ext2_path(getattr(args, "path", ""))
    if rel == "":
        print("paceflash: cat requires a file path", file=sys.stderr)
        return 1
    try:
        with open_opentla4_ext2(
            flash_path,
            _cmdline_from_args(args),
            slice_name=args.tl_slice,
            nand_translate=not args.no_nand_translate,
            nand_translate_mode=args.nand_mode,
            bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
        ) as vol:
            data = read_ext2_regular_file(
                vol.slice_bytes,
                rel,
                sb_off=vol.sb_off,
                access=vol.access,
                cmdb_recover=getattr(args, "cmdb_recover", False),
            )
    except IsADirectoryError as e:
        print(f"paceflash: is a directory: {e}", file=sys.stderr)
        return 1
    except (FileNotFoundError, OSError) as e:
        print(f"paceflash: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"paceflash: {e}", file=sys.stderr)
        return 1

    _warn_cmdb_stride_corruption(data, rel)
    out_path = getattr(args, "output", None)
    if out_path is None:
        _warn_binary_cat_to_tty(data)
    if out_path is not None:
        Path(out_path).expanduser().write_bytes(data)
        print(f"paceflash: wrote {len(data)} bytes to {Path(out_path).resolve()}", file=sys.stderr)
        return 0

    sys.stdout.buffer.write(data)
    return 0


def _print_wrapped_block(text: str, *, width: int = 88, indent: str = "  ") -> None:
    """Print a long message with word wrap (terminal-friendly)."""
    for line in textwrap.wrap(text, width=width, break_long_words=False):
        print(f"{indent}{line}")


def _print_factory_params_human(doc: dict[str, Any]) -> None:
    print(f"Flash: {doc.get('flash')}")
    lp = doc.get("loader_partition")
    if isinstance(lp, dict):
        print(
            f"Loader MTD: offset={lp.get('offset')} size={lp.get('size')} "
            f"(index {lp.get('index')})"
        )
    fac = doc.get("factory") or {}
    if not fac.get("ok"):
        print(f"Factory params: {fac.get('error', fac)}")
    else:
        print(f"Factory block: loader+{fac.get('offset', 0):#x} ({fac.get('region_bytes')} bytes)")
        params = fac.get("params") or {}
        for key in sorted(params.keys()):
            val = str(params[key])
            if len(val) > 100:
                val = val[:100] + "…"
            print(f"  {key}={val}")
        unknown = fac.get("unknown_keys") or []
        if unknown:
            print(f"  (unknown keys: {', '.join(unknown)})")
    for w in doc.get("warnings") or []:
        print(f"paceflash: warning: {w}", file=sys.stderr)


def _print_dump_http_auth_human(doc: dict[str, Any]) -> None:
    print(f"Flash: {doc.get('flash')}")
    print(doc.get("hurl_note", ""))
    print("\nHTTP auth realms (configured surfaces):")
    for r in doc.get("http_auth_realms") or []:
        print(
            f"  {r.get('surface')}: {r.get('auth_type')} "
            f"realm={r.get('realm')} backend={r.get('backend', '')}"
        )
    fh = doc.get("factory_http") or {}
    if fh:
        print("\nFactory (loader) HTTP-related defaults:")
        for k in sorted(fh.keys()):
            print(f"  {k}={fh[k]}")
    print(doc.get("accesscode_hint", ""))
    for block in doc.get("cmdb_ext2") or []:
        path = block.get("path")
        if not block.get("ok"):
            print(f"\nCMDB {path}: {block.get('error')}")
            continue
        print(f"\nCMDB {path} ({block.get('bytes')} bytes, {block.get('encoding')}):")
        for u in block.get("users") or []:
            print(
                f"  user={u.get('user')!r} groups={u.get('groups')!r} "
                f"password={u.get('password')!r} hint={u.get('hint')!r}"
            )
    for block in doc.get("tlpart_user_tables") or []:
        off = block.get("offset")
        off_s = f"{off:#x}" if isinstance(off, int) else "?"
        print(f"\ntlpart embedded user table @{off_s}:")
        for u in block.get("users") or []:
            print(f"  user={u.get('user')!r} password={u.get('password')!r}")
    for w in doc.get("warnings") or []:
        print(f"paceflash: warning: {w}", file=sys.stderr)


def _run_dump_http_auth(args: argparse.Namespace, flash_path: Path) -> int:
    doc = dump_http_auth(
        flash_path,
        cmdline=_cmdline_from_args(args),
        nand_translate=not getattr(args, "no_nand_translate", False),
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
        redact=getattr(args, "redact", False),
        decode_password_hashes=getattr(args, "decode_hashes", False),
        include_tlpart_scan=not getattr(args, "no_tlpart_scan", False),
    )
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_dump_http_auth_human(doc)
    return 0 if doc.get("ok") else 1


def _print_dump_eapol_cert_human(doc: dict[str, Any]) -> None:
    print(f"Flash: {doc.get('flash')}")
    print(f"Cert: {doc.get('cert')}")
    if doc.get("serial"):
        print(f"Serial: {doc.get('serial')}")
    if not doc.get("ok"):
        print(f"EAPOL cert: {doc.get('error', doc)}")
        return
    if doc.get("decrypted"):
        print(f"Subject: {doc.get('subject', '(unknown)')}")
        print(f"PEM: {doc.get('pem_bytes')} bytes")
        if doc.get("pem_path"):
            print(f"Wrote PEM: {doc['pem_path']}")
    if doc.get("p12_path"):
        print(f"Wrote PKCS#12: {doc['p12_path']}")
    elif doc.get("p12_bytes"):
        print(f"PKCS#12: {doc['p12_bytes']} bytes (encrypted)")
    if doc.get("password") and not doc.get("password", "").startswith("***"):
        print(f"Password: {doc['password']!r}")
    for w in doc.get("warnings") or []:
        print(f"paceflash: warning: {w}", file=sys.stderr)


def _run_dump_eapol_cert(args: argparse.Namespace, flash_path: Path) -> int:
    cert = getattr(args, "cert", "lightspeed")
    decrypt = not getattr(args, "no_decrypt", False)
    stdout_pem = getattr(args, "stdout_pem", False)
    doc = dump_eapol_cert(
        flash_path,
        cert=cert,
        cmdline=_cmdline_from_args(args),
        nand_translate=not getattr(args, "no_nand_translate", False),
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        decrypt=decrypt,
        output_pem=None if stdout_pem else getattr(args, "output", None),
        output_p12=getattr(args, "p12", None),
        redact_password=getattr(args, "redact", False),
        include_pem=stdout_pem,
    )
    if stdout_pem and doc.get("ok") and doc.get("decrypted"):
        pem = doc.get("pem")
        if not isinstance(pem, str):
            print("paceflash: --stdout-pem requires successful decrypt", file=sys.stderr)
            return 1
        sys.stdout.write(pem)
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_dump_eapol_cert_human(doc)
    return 0 if doc.get("ok") else 1


def _print_paramtool_human(doc: dict[str, Any]) -> None:
    print(f"Flash: {doc.get('flash')}")
    if not doc.get("ok"):
        print(f"paramtool: {doc.get('error', doc)}")
        if doc.get("known_keys"):
            print("Known keys:", ", ".join(doc["known_keys"]))
        return
    if doc.get("mode") == "get":
        print(f"{doc.get('key')}={doc.get('value')}")
        if doc.get("value_bytes") is not None:
            print(f"  ({doc['value_bytes']} bytes)")
        if doc.get("value_sha256"):
            print(f"  sha256={doc['value_sha256']}")
        return
    print(f"Parameters ({doc.get('param_count', 0)}):")
    params = doc.get("params") or {}
    sources = doc.get("sources") or {}
    for k in sorted(params.keys()):
        val = str(params[k])
        if len(val) > 80:
            val = val[:80] + "…"
        src = sources.get(k, "")
        suffix = f"  [{src}]" if src else ""
        print(f"  {k}={val}{suffix}")
    if doc.get("crc_meta"):
        cm = doc["crc_meta"]
        print(
            f"CRC layout: stored={cm.get('stored_crc32')} "
            f"calc={cm.get('calc_crc32')} blob={cm.get('blob_bytes')} B"
        )


def _run_paramtool(args: argparse.Namespace, flash_path: Path) -> int:
    mode = "get" if getattr(args, "get", None) else "show"
    doc = dump_paramtool(
        flash_path,
        mode=mode,
        key=getattr(args, "get", None),
        cmdline=_cmdline_from_args(args),
        nand_translate=not getattr(args, "no_nand_translate", False),
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        redact=getattr(args, "redact", False),
        include_p12_b64=not getattr(args, "no_p12", False),
    )
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_paramtool_human(doc)
    if doc.get("ok") and mode == "get" and getattr(args, "output", None):
        val = doc.get("value")
        if isinstance(val, str):
            Path(args.output).expanduser().write_text(val, encoding="ascii", errors="replace")
            print(f"Wrote {doc['key']} to {Path(args.output).resolve()}", file=sys.stderr)
    return 0 if doc.get("ok") else 1


def _run_factory_params(args: argparse.Namespace, flash_path: Path) -> int:
    nand_translate = not getattr(args, "no_nand_translate", False)
    doc = dump_factory_params(
        flash_path,
        cmdline=_cmdline_from_args(args),
        nand_translate=nand_translate,
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        hint_offset=getattr(args, "offset", None),
        redact=getattr(args, "redact", False),
    )
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_factory_params_human(doc)
    fac = doc.get("factory") or {}
    return 0 if fac.get("ok") else 1


def _print_human(inv: dict[str, Any]) -> None:
    print(f"flash: {inv['flash_path']}")
    print(f"size: {inv['file_size_bytes']} bytes (mtdparts reference: {inv['logical_reference_bytes']})")
    print(f"cmdline: {inv['cmdline']!r}")
    nt = inv.get("nand_translate")
    if isinstance(nt, dict) and nt.get("ran"):
        extra = f" mode={nt.get('resolved_mode')!r}" if nt.get("resolved_mode") is not None else ""
        if nt.get("error"):
            print(f"nand_translate: ran (error: {nt['error']})")
        else:
            print(f"nand_translate: ran{extra} logical_size={nt.get('logical_size')}")
        bci = nt.get("bbm_chain_infer")
        if isinstance(bci, dict):
            print(
                "nand_translate BBM infer: "
                f"want_chain={bci.get('want_chain')} "
                f"chain_applied={bci.get('chain_applied')} "
                f"flat_spare_path_ok={bci.get('flat_spare_path_ok')} "
                f"virt_before={bci.get('virt_nand_page_table_mode_before_apply')!r} "
                f"virt_after={bci.get('virt_nand_page_table_mode_after_decision')!r}"
            )
    elif isinstance(nt, dict) and nt.get("skipped"):
        print("nand_translate: skipped (--no-nand-translate or raw-only path)")
    print()
    print("MTD:")
    for row in inv["mtd"]:
        rem = " (remainder)" if row.get("remainder") else ""
        print(f"  mtd{row['index']:d} {row['name']!r} @ {row['offset']:#x} size {row['size']:#x}{rem}")
    print()
    bbm = inv.get("bbm_virtual_scan")
    if isinstance(bbm, dict) and bbm.get("attached"):
        print("BBM virtual scan:")
        print(
            f"  mode={bbm.get('bbm_mode')!r} "
            f"virt_page_table={bbm.get('virt_nand_page_table_mode')!r} "
            f"holes={bbm.get('hole_erase_blocks')}/{bbm.get('virt_blocks')} virt erase blocks"
        )
        print(
            f"  tlpart_tl_scan_bytes_len={bbm.get('tlpart_tl_scan_bytes_len')} "
            f"head_sha256_16={bbm.get('tlpart_tl_scan_head_sha256_16')}"
        )
        if bbm.get("chain_aware_virtual_scan"):
            print("  chain_aware_virtual_scan: true")
        print()
    dump_info = inv.get("tl_slice_dump")
    if isinstance(dump_info, dict) and dump_info.get("path"):
        bw = dump_info.get("bytes_written")
        sl = dump_info.get("slice")
        print(f"TL slice dump: {dump_info['path']} ({bw} bytes, slice={sl!r})")
        print()
    tl = inv["tl"]
    print("TL disklabel (tlpart):")
    if isinstance(tl, dict) and tl.get("ok"):
        print(f"  anchor_kind={tl['anchor_kind']!r} anchor_offset={tl['anchor_offset']:#x}")
        for w in tl.get("warnings", []):
            print(f"  warning: {w}")
        for s in tl.get("slices", []):
            print(
                f"  {s['name']!r} off {s['offset_bytes']:#x} len {s['length_bytes']:#x} "
                f"start_sector={s['start_sector']} num_sectors={s['num_sectors']}"
            )
    else:
        err = tl.get("error", "unknown") if isinstance(tl, dict) else tl
        if isinstance(err, str) and len(err) > 100:
            print("  (not available:")
            _print_wrapped_block(err, indent="    ")
            print("  )")
        else:
            print(f"  (not available: {err})")
    print()
    sq = inv.get("squashfs")
    print("SquashFS in ext2 files (dissect.squashfs on sys1/rootimage.img, etc.):")
    if sq is None:
        print("  (skipped)")
    elif isinstance(sq, dict):
        if sq.get("error"):
            err = sq["error"]
            if isinstance(err, str) and len(err) > 100:
                print("  (")
                _print_wrapped_block(err, indent="    ")
                print("  )")
            else:
                print(f"  ({err})")
        elif sq.get("root_ls") is not None:
            src = sq.get("source")
            src_note = f" from {src}" if src else ""
            sb = sq.get("squashfs_superblock_offset")
            sb_note = f" @ superblock {sb:#x}" if sb is not None else ""
            parts = []
            for ent in sq["root_ls"]:
                k = ent.get("kind", "?")
                parts.append(f"{ent.get('name', '')!r}({k})")
            line = ", ".join(parts[:24])
            if len(parts) > 24:
                line += " …"
            print(f"  slice={sq.get('slice')!r}{src_note}{sb_note}: {line}")
        else:
            print("  (empty)")
    unc = inv.get("upgrade_nand_correlation")
    if isinstance(unc, dict):
        print()
        print("Upgrade NAND correlation (pkgstream squash fingerprints):")
        indexed = unc.get("carrier_releases_indexed") or []
        if indexed:
            print(f"  indexed releases ({len(indexed)}): {', '.join(indexed[:8])}{' …' if len(indexed) > 8 else ''}")
        for rel in unc.get("matched_releases") or []:
            print(
                f"  MATCH {rel.get('release_label')!r} "
                f"{rel.get('matched_path')!r} via {rel.get('match_kind')} "
                f"on {rel.get('nand_source')!r} hsqs={rel.get('hsqs_offset')}"
            )
        hint = unc.get("best_dissect_hint")
        if isinstance(hint, dict):
            print(
                f"  best dissect hint: {hint.get('source')!r} "
                f"sb={hint.get('squashfs_superblock_offset')} "
                f"bytes={hint.get('squashfs_image_bytes')} "
                f"release={hint.get('release_label')!r}"
            )
        elif indexed:
            print("  (no fingerprint match in scanned TL views)")
        for w in unc.get("warnings") or []:
            print(f"  warning: {w}")
    mpp = inv.get("mtd_partition_probes")
    if isinstance(mpp, dict):
        print()
        print("MTD partition probes (loader / mtdoops linear slices):")
        loader_p = mpp.get("loader")
        if isinstance(loader_p, dict):
            if loader_p.get("ok") and isinstance(loader_p.get("env"), dict):
                env = loader_p["env"]
                print(f"  loader env: size={env.get('env_size')} crc_ok={env.get('crc_ok')}")
                if env.get("mtdparts_token"):
                    print(f"    mtdparts: {env['mtdparts_token']}")
                for k in ("bootcmd", "ver", "version", "serial#"):
                    hk = f"highlight_{k}"
                    if hk in env:
                        v = str(env[hk])
                        print(f"    {k}: {v[:120]}{'…' if len(v) > 120 else ''}")
            else:
                print(f"  loader: {loader_p.get('error', loader_p)}")
        mtd_p = mpp.get("mtdoops")
        if isinstance(mtd_p, dict):
            if mtd_p.get("ok"):
                print(
                    f"  mtdoops: erased_ratio={mtd_p.get('erased_byte_ratio')} "
                    f"used_slots={len(mtd_p.get('used_slots') or [])} "
                    f"ascii_runs={mtd_p.get('ascii_run_count')}"
                )
            else:
                print(f"  mtdoops: {mtd_p.get('error', mtd_p)}")
        for w in mpp.get("warnings") or []:
            print(f"  warning: {w}")
    print()
    ext2 = inv.get("ext2")
    print("ext2 root listing:")
    if ext2 is None:
        print("  (skipped)")
    elif isinstance(ext2, dict):
        if ext2.get("error"):
            err = ext2["error"]
            if isinstance(err, str) and len(err) > 100:
                print("  (")
                _print_wrapped_block(err, indent="    ")
                print("  )")
            else:
                print(f"  ({err})")
        elif ext2.get("root_ls") is not None:
            names = [str(x.get("name", "")) for x in ext2["root_ls"]]
            print(f"  slice={ext2.get('slice')!r}: {', '.join(names[:20])}{' …' if len(names) > 20 else ''}")
        else:
            print("  (empty)")
    embedded = None
    o4 = inv.get("opentla4_extract")
    if isinstance(o4, dict):
        embedded = o4.get("embedded_squash_images") or o4.get("squash_file_probe")
    if embedded is None and isinstance(ext2, dict):
        embedded = ext2.get("embedded_squash_images") or ext2.get("squash_file_probe")
    if isinstance(embedded, list) and embedded:
        print()
        print("Embedded SquashFS images (files inside ext2, not ext2 volumes):")
        for row in embedded:
            path = row.get("path", "?")
            kind = row.get("content_kind", "squashfs")
            ok = row.get("ok")
            status = row.get("status") or ("ok" if ok else "unavailable")
            print(f"  {path!r} ({kind}, {status})")
    print()
    print("ubi.mtd= attachments:")
    for row in inv["ubi_attach"]:
        sub = f", offset {row['mtd_sub_offset']:#x}" if row.get("mtd_sub_offset") is not None else ""
        print(f"  {row['raw_token']!r} -> ref {row['mtd_ref']!r}{sub}")
    for scan in inv["ubi_vid_scans"]:
        if scan.get("error"):
            err = scan["error"]
            if isinstance(err, str) and len(err) > 100:
                print(f"  VID scan {scan.get('mtd_ref')!r}:")
                _print_wrapped_block(err, indent="    ")
            else:
                print(f"  VID scan {scan.get('mtd_ref')!r}: {err}")
        else:
            n = len(scan.get("vid_hits", []))
            print(f"  VID scan {scan.get('mtd_ref')!r} on {scan.get('backing_label')!r}: {n} hit(s)")


def _run_ls_inventory(args: argparse.Namespace, flash_path: Path) -> int:
    debug = bool(getattr(args, "debug", False))
    if debug:
        configure_opentl_stderr_logging()

    with _tl_disk_probe_report_env(getattr(args, "tl_probe_report", False)):
        inv = build_inventory(
            flash_path,
            cmdline=_cmdline_from_args(args),
            include_ext2_root=not args.no_ext2,
            include_squashfs_root=debug and not args.no_squashfs,
            tl_slice=args.tl_slice,
            ubi_erase_bytes=args.ubi_erase_bytes,
            nand_translate=not args.no_nand_translate,
            nand_translate_mode=args.nand_mode,
            bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
            dump_tl_slice_out=args.dump_tl_slice,
            lib2spy_json=getattr(args, "lib2spy_json", None),
            pkgstream_path=getattr(args, "pkgstream", None),
            firmware_collection=getattr(args, "firmware_collection", None),
            carrier_index_json=_resolve_carrier_index_arg(
                getattr(args, "firmware_collection", None),
                getattr(args, "carrier_index", None),
            ),
            probe_loader_env=getattr(args, "probe_loader_env", False),
            probe_mtdoops=getattr(args, "probe_mtdoops", False),
            mtdoops_record_size=getattr(args, "mtdoops_record_size", 131072),
            dump_opentla4_ext2=getattr(args, "dump_opentla4_ext2", None),
            extract_ext2_dir=getattr(args, "extract_ext2_dir", None),
            debug=debug,
        )
    warnings = inv.get("warnings", [])
    if debug and isinstance(warnings, list):
        _emit_warnings([str(w) for w in warnings])
    elif isinstance(warnings, list):
        for w in warnings:
            s = str(w)
            if s.startswith("nand_translate failed:") or s.startswith("paceflash: opentla4 extract failed"):
                _emit_warnings([s])

    if args.json:
        print(json.dumps(inv, indent=2))
    else:
        _print_human(inv)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="paceflash",
        description="List or read opentla4 ext2 on a Pace flash dump; use --debug for full inventory.",
    )
    _add_global_flash_options(ap)
    sub = ap.add_subparsers(dest="command", required=True)
    ls = sub.add_parser(
        "ls",
        help="List a directory on the TL slice ext2 volume (default /)",
    )
    _add_global_flash_options(ls, suppress_if_unset=True)
    _add_subcommand_common_args(ls)
    _add_operands_arg(
        ls,
        metavar="[FLASH] [PATH]",
        help_text=(
            "With --flash: ext2 directory (default /). Otherwise: flash dump path, then optional ext2 path"
        ),
    )
    ls.add_argument("-a", "--all", action="store_true", help="Include . and .. entries")
    ls.add_argument("-l", "--long", action="store_true", help="Long listing (mode + name)")
    ls.add_argument("--json", action="store_true", help="JSON directory listing, or full inventory with --debug")
    ls.add_argument(
        "--debug",
        action="store_true",
        help="Full flash inventory (MTD, BBM, TL, UBI) instead of a single-directory listing",
    )
    ls.add_argument("--no-ext2", action="store_true", help="With --debug: skip ext2 carve")
    ls.add_argument(
        "--no-squashfs",
        action="store_true",
        help="With --debug: skip embedded SquashFS probes in ext2",
    )
    ls.add_argument(
        "--ubi-erase-bytes",
        type=int,
        default=131072,
        metavar="N",
        help="With --debug: PEB erase size for UBI VID scan (default 131072)",
    )
    ls.add_argument(
        "--tl-probe-report",
        action="store_true",
        help="With --debug: emit TLDiskProbeReport on TL enumeration failure",
    )
    ls.add_argument(
        "--dump-tl-slice",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Write raw TL child partition bytes for --tl-slice to PATH (SquashFS magic may not be at offset 0)"
        ),
    )
    ls.add_argument(
        "--dump-opentla4-ext2",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Write assembled opentla4 ext2 partition image (same bytes as --dump-tl-slice when "
            "--tl-slice opentla4); use debugfs/e2tools on the output"
        ),
    )
    ls.add_argument(
        "--extract-ext2-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Extract sys1/rootimage.img, sys2/rootimage.img, etc. from opentla4 ext2 into DIR "
            "(writes manifest.json with sizes and strict squash SHA when applicable)"
        ),
    )
    ls.add_argument(
        "--lib2spy-json",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "lib2spy verify JSON for carrier squash FILE fingerprints; enables upgrade_nand_correlation "
            "and anchored SquashFS dissect/carve on TL views"
        ),
    )
    ls.add_argument(
        "--pkgstream",
        type=Path,
        default=None,
        metavar="PATH",
        help="Optional .pkgstream path to compute SHA-256 carrier refs (with --lib2spy-json)",
    )
    ls.add_argument(
        "--firmware-collection",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Device firmware tree (e.g. firmware/00D09E): correlate NAND against every install "
            ".pkgstream under DIR (rootimage.img + ui.img). Overrides --lib2spy-json when set."
        ),
    )
    ls.add_argument(
        "--carrier-index",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Prebuilt carrier digest JSON from `paceflash build-carrier-index` "
            f"(default tries {_DEFAULT_CARRIER_INDEX} when using --firmware-collection)"
        ),
    )
    ls.add_argument(
        "--probe-loader-env",
        action="store_true",
        help="Parse U-Boot env v1 at loader MTD base (linear slice; bootcmd/mtdparts)",
    )
    ls.add_argument(
        "--probe-mtdoops",
        action="store_true",
        help="Scan mtdoops MTD slice for panic/oops records (linear; default record_size 131072)",
    )
    ls.add_argument(
        "--mtdoops-record-size",
        type=int,
        default=131072,
        metavar="N",
        help="mtdoops record_size for --probe-mtdoops (default 131072 per fwupgrade cmdline)",
    )

    sh = sub.add_parser(
        "shell",
        help="Interactive ext2 shell (flash loaded once; ls, cd, cat, pwd)",
    )
    _add_global_flash_options(sh, suppress_if_unset=True)
    _add_subcommand_common_args(sh)
    _add_operands_arg(
        sh,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash before shell)",
    )
    sh.add_argument(
        "-c",
        "--command",
        dest="shell_command",
        metavar="CMD",
        help="Run one shell command and exit (non-interactive)",
    )

    cat = sub.add_parser("cat", help="Print a regular file from the TL slice ext2 volume")
    cat.add_argument(
        "--output",
        "-o",
        type=Path,
        metavar="FILE",
        help="Write file bytes to FILE instead of stdout (avoids PowerShell text redirect)",
    )
    cat.add_argument(
        "--cmdb-recover",
        action="store_true",
        help="Physical CMDB extent recovery (not kernel ext2); default is kernel-faithful read",
    )
    _add_global_flash_options(cat, suppress_if_unset=True)
    _add_subcommand_common_args(cat)
    _add_operands_arg(
        cat,
        metavar="[FLASH] PATH",
        help_text=(
            "With --flash: ext2 file path. Otherwise: flash dump path then ext2 file path"
        ),
    )

    ha = sub.add_parser(
        "dump-http-auth",
        help="Dump httpd auth realms map, factory access codes, and CMDB user passwords",
    )
    _add_global_flash_options(ha, suppress_if_unset=True)
    _add_nand_args(ha)
    _add_operands_arg(
        ha,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)",
    )
    ha.add_argument(
        "--redact",
        action="store_true",
        help="Mask accesscode/Wi‑Fi/CM password fields in output",
    )
    ha.add_argument(
        "--decode-hashes",
        action="store_true",
        help="Include hex of base64 CM password blobs (lab only)",
    )
    ha.add_argument(
        "--no-tlpart-scan",
        action="store_true",
        help="Skip scanning assembled tlpart for embedded CM user tables",
    )
    ha.add_argument("--json", action="store_true")

    eap = sub.add_parser(
        "dump-eapol-cert",
        help="Extract lightspeed/device PKCS#12 from assembled tlpart and decrypt to PEM",
    )
    _add_global_flash_options(eap, suppress_if_unset=True)
    _add_nand_args(eap)
    _add_operands_arg(
        eap,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)",
    )
    eap.add_argument(
        "--cert",
        choices=("lightspeed", "device"),
        default="lightspeed",
        help="Which *_p12= blob to extract (default lightspeed / WAN EAPOL)",
    )
    eap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write decrypted PEM to FILE (default ./{cert}_{CN}_eapol.pem from cert subject)",
    )
    eap.add_argument(
        "--p12",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write raw PKCS#12 to FILE (default ./{cert}_{CN}.p12 from cert subject)",
    )
    eap.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Only extract and write PKCS#12 from flash (no cryptography / PEM)",
    )
    eap.add_argument(
        "--stdout-pem",
        action="store_true",
        help="Write decrypted PEM to stdout instead of -o",
    )
    eap.add_argument(
        "--redact",
        action="store_true",
        help="Omit devkey/password from --json (safe for logs)",
    )
    eap.add_argument("--json", action="store_true")

    fp = sub.add_parser(
        "factory-params",
        help="Dump factory manufacturing key=value block from loader MTD (sn, mac, …)",
    )
    _add_global_flash_options(fp, suppress_if_unset=True)
    _add_nand_args(fp)
    _add_operands_arg(
        fp,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)",
    )
    fp.add_argument(
        "--offset",
        type=lambda x: int(x, 0),
        default=None,
        metavar="OFF",
        help=f"Hint offset of model= in loader (default auto; PACE ~{0x1FF84:#x})",
    )
    fp.add_argument(
        "--redact",
        action="store_true",
        help="Mask devkey/authcode/wifi secrets in output (safe for logs)",
    )
    fp.add_argument("--json", action="store_true")

    pt = sub.add_parser(
        "paramtool",
        help="Dump board_param / paramtool keys (gw:*) from assembled tlpart (offline RE)",
    )
    _add_global_flash_options(pt, suppress_if_unset=True)
    _add_nand_args(pt)
    _add_operands_arg(
        pt,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)",
    )
    pt.add_argument(
        "--get",
        metavar="KEY",
        default=None,
        help="Get one key (e.g. gw:trust_engcert); default is --show all keys found",
    )
    pt.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="With --get: write value to FILE (mirrors paramtool -get NAME -out FILE)",
    )
    pt.add_argument(
        "--no-p12",
        action="store_true",
        help="Omit *_p12 base64 blobs from listing (gw:* keys only)",
    )
    pt.add_argument(
        "--redact",
        action="store_true",
        help="Mask *_p12 and other sensitive values",
    )
    pt.add_argument("--json", action="store_true")

    bci = sub.add_parser(
        "build-carrier-index",
        help="Precompute rootimage/ui squash SHA-256 refs for all 00D09E install pkgstreams",
    )
    bci.add_argument(
        "firmware_collection",
        type=Path,
        metavar="DIR",
        help="Firmware device tree root (e.g. …/firmware/00D09E)",
    )
    bci.add_argument(
        "--out",
        type=Path,
        default=_DEFAULT_CARRIER_INDEX,
        metavar="PATH",
        help=f"Output JSON cache path (default {_DEFAULT_CARRIER_INDEX})",
    )

    args = ap.parse_args(argv)

    if args.command == "build-carrier-index":
        doc = build_carrier_index(args.firmware_collection, args.out)
        print(
            json.dumps(
                {
                    "out": str(Path(args.out).resolve()),
                    "carrier_count": doc.get("carrier_count"),
                    "ref_rows": len(doc.get("refs") or []),
                },
                indent=2,
            )
        )
        return 0

    if args.command == "ls":
        flash_path, ext2_path = _resolve_flash_and_path_operands(args, require_path=False)
        if getattr(args, "debug", False):
            return _run_ls_inventory(args, flash_path)
        return _run_ls_path(args, flash_path, ext2_path=ext2_path)

    if args.command == "cat":
        flash_path, ext2_path = _resolve_flash_and_path_operands(args, require_path=True)
        if not ext2_path:
            print("paceflash: cat requires PATH (file on ext2)", file=sys.stderr)
            return 2
        args.path = ext2_path
        return _run_cat(args, flash_path)

    if args.command == "shell":
        flash_path = _resolve_flash_path(args)
        return _run_shell(args, flash_path)

    if args.command == "dump-http-auth":
        flash_path = _resolve_flash_path(args)
        return _run_dump_http_auth(args, flash_path)

    if args.command == "dump-eapol-cert":
        flash_path = _resolve_flash_path(args)
        return _run_dump_eapol_cert(args, flash_path)

    if args.command == "factory-params":
        flash_path = _resolve_flash_path(args)
        return _run_factory_params(args, flash_path)

    if args.command == "paramtool":
        flash_path = _resolve_flash_path(args)
        return _run_paramtool(args, flash_path)

    return 2
