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
    read_ext2_regular_file)

from paceflash.board_info import dump_board_info
from paceflash.board_param import dump_paramtool
from paceflash.cmdb_fw import dump_cmdb_fw
from paceflash.cmdb_parse import list_table_names, read_cmdb_text
from paceflash.flash_session import open_opentla4_ext2
from paceflash.flash_patch import patch_trust_engcert_flash
from paceflash.eapol_cert import dump_eapol_cert
from paceflash.network_config import gen_network_config
from paceflash.factory_params import dump_factory_params
from paceflash.http_auth import dump_http_auth
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
    carrier_index: Path | None) -> Path | None:
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
    require_path: bool) -> tuple[Path, str]:
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
        help="Logicalize full-chip Pace physical dumps before TL/ext2 (default)")
    nand_grp.add_argument(
        "--no-nand-translate",
        action="store_true",
        help="Skip in-memory NAND logicalize (raw packed image only)")
    ap.add_argument(
        "--nand-mode",
        choices=("inline-2112", "flat-tail", "identity"),
        default="inline-2112",
        help="NAND translate mode for full-chip physical dumps (default inline-2112)")
    ap.add_argument(
        "--bbm-chain-aware",
        action="store_true",
        help="Force spare-chain BBM virtual scan after NAND translate")


def _add_global_flash_options(
    ap: argparse.ArgumentParser,
    *,
    suppress_if_unset: bool = False) -> None:
    """``--flash`` / ``--cmdline`` before or after the subcommand (``paceflash --flash X ls``)."""
    unset = argparse.SUPPRESS if suppress_if_unset else None
    ap.add_argument(
        "--flash",
        type=Path,
        dest="flash_opt",
        default=unset,
        metavar="PATH",
        help="Flash dump path (alternative to positional FLASH on ls/cat)")
    ap.add_argument(
        "--cmdline",
        type=str,
        default=unset,
        help="Kernel cmdline with mtdparts= (default: quiet rw + unand.mtd.DEFAULT_MTDPARTS)")


def _add_subcommand_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--tl-slice",
        type=str,
        default="opentla4",
        metavar="NAME",
        help="TL slice holding ext2 (default opentla4)")
    _add_nand_args(ap)


def _add_operands_arg(
    ap: argparse.ArgumentParser,
    *,
    metavar: str,
    help_text: str) -> None:
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
            bbm_chain_aware=getattr(args, "bbm_chain_aware", False)) as vol:
            rows = list_ext2_directory(
                vol.slice_bytes,
                rel,
                sb_off=vol.sb_off,
                include_dot=getattr(args, "all", False),
                access=vol.access)
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
                indent=2)
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
        bbm_chain_aware=getattr(args, "bbm_chain_aware", False))
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
        file=sys.stderr)


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
            file=sys.stderr)


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
            bbm_chain_aware=getattr(args, "bbm_chain_aware", False)) as vol:
            data = read_ext2_regular_file(
                vol.slice_bytes,
                rel,
                sb_off=vol.sb_off,
                access=vol.access,
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


def _print_dump_cmdb_fw_human(doc: dict[str, Any], *, pinholes_only: bool = False) -> None:
    if doc.get("flash"):
        print(f"Flash: {doc.get('flash')}")
    if doc.get("cmdb_path"):
        print(f"CMDB: {doc.get('cmdb_path')}")
    sources = doc.get("sources") or []
    if not sources:
        print("No CMDB sources read.")
    for src in sources:
        label = src.get("path") or src.get("source") or "?"
        if not src.get("ok"):
            print(f"\n== {label} ==\n  error: {src.get('error')}")
            continue
        print(f"\n== {label} ({src.get('encoding')}, {src.get('bytes')} bytes) ==")
        if src.get("firmware_version"):
            print(f"Firmware: {src.get('firmware_version')}")
        pinholes = src.get("pinholes") or []
        print(f"\nPinholes (hostapps): {len(pinholes)}")
        if pinholes:
            for p in pinholes:
                ports = p.get("ports") or []
                port_txt = ", ".join(
                    f"{pr.get('proto')} {pr.get('start_port')}-{pr.get('end_port')}"
                    for pr in ports[:4]
                )
                print(
                    f"  mapid={p.get('mapid')!r} node={p.get('node_name')!r} "
                    f"({p.get('node_ip')}) app={p.get('app_name')!r} id={p.get('app_id')} "
                    f"ports=[{port_txt}]"
                )
                extra = {
                    k: v
                    for k, v in (p.get("hostapps") or {}).items()
                    if k not in {"mapid", "MAPID", "nodeid", "app_id", "appid"}
                }
                if extra:
                    print(f"    hostapps: {extra}")
        else:
            print("  (none — empty hostapps table)")
        if pinholes_only:
            continue
        fw = src.get("fw") or {}
        if fw:
            print("\nFirewall (fw):")
            if fw.get("inbound"):
                print(f"  inbound: {fw.get('inbound')}")
            if fw.get("outbound"):
                print(f"  outbound: {fw.get('outbound')}")
            params = fw.get("params") or {}
            for key in sorted(params):
                print(f"  {key}: {params[key]}")
        rules = src.get("rules") or {}
        for rname in ("fwrules", "firewall_rule", "bind", "fw6_rule"):
            rows = rules.get(rname) or []
            if not rows:
                continue
            print(f"\n{rname}: {len(rows)} row(s)")
            for row in rows[:20]:
                if rname == "fwrules":
                    rule = str(row.get("rule") or "").replace("&gt;", ">").replace("&lt;", "<")
                    print(f"  order {row.get('order')}: {rule}")
                elif rname == "bind":
                    print(
                        f"  {row.get('bindid')}: {row.get('state')} "
                        f"{row.get('proto')} {row.get('portstatic')} app={row.get('appid')}"
                    )
                elif rname == "fw6_rule":
                    print(
                        f"  {row.get('alias')}: {row.get('chain')} -> "
                        f"{row.get('target_chain')} ({row.get('description')})"
                    )
                else:
                    print(f"  row {row.get('row')}: {row}")
            if len(rows) > 20:
                print(f"  ... {len(rows) - 20} more")
    tlpart = doc.get("tlpart_cmdb") or []
    if tlpart and not pinholes_only:
        print(f"\nEmbedded tlpart CMDB chunks with firewall tables: {len(tlpart)}")
        for block in tlpart[:3]:
            print(
                f"  offset=0x{block.get('offset', 0):x} "
                f"pinholes={len(block.get('pinholes') or [])} "
                f"fw={'yes' if block.get('fw') else 'no'}"
            )
    for w in doc.get("warnings") or []:
        print(f"paceflash: warning: {w}", file=sys.stderr)


def _run_dump_cmdb_fw(args: argparse.Namespace, flash_path: Path | None) -> int:
    tables = None
    if getattr(args, "tables", None):
        tables = tuple(t.strip() for t in args.tables.split(",") if t.strip())
    doc = dump_cmdb_fw(
        flash_path=flash_path,
        cmdb_path=getattr(args, "cmdb", None),
        cmdline=_cmdline_from_args(args),
        nand_translate=not getattr(args, "no_nand_translate", False),
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
        include_tlpart_scan=not getattr(args, "no_tlpart_scan", False),
        tables=tables,
        include_catalog=getattr(args, "catalog", False))
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_dump_cmdb_fw_human(doc, pinholes_only=getattr(args, "pinholes_only", False))
    return 0 if doc.get("ok") else 1


def _run_cmdb_list_tables(args: argparse.Namespace) -> int:
    cmdb = getattr(args, "cmdb", None)
    if cmdb is None:
        print("paceflash: cmdb-list-tables requires --cmdb PATH", file=sys.stderr)
        return 2
    text, enc = read_cmdb_text(Path(cmdb).read_bytes())
    names = list_table_names(text)
    if args.json:
        print(json.dumps({"cmdb": str(cmdb), "encoding": enc, "tables": names}, indent=2))
    else:
        print(f"CMDB: {cmdb} ({enc})")
        print(f"Tables: {len(names)}")
        for n in names:
            print(f"  {n}")
    return 0


def _run_dump_http_auth(args: argparse.Namespace, flash_path: Path) -> int:
    doc = dump_http_auth(
        flash_path,
        cmdline=_cmdline_from_args(args),
        nand_translate=not getattr(args, "no_nand_translate", False),
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
        redact=getattr(args, "redact", False),
        decode_password_hashes=getattr(args, "decode_hashes", False),
        include_tlpart_scan=not getattr(args, "no_tlpart_scan", False))
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
        include_pem=stdout_pem)
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


def _print_gen_network_config_human(doc: dict[str, Any]) -> None:
    if not doc.get("ok"):
        print(f"gen-network-config: {doc.get('error', doc)}")
        return
    print(f"Profile: {doc.get('profile')}")
    print(f"Interface: {doc.get('interface')}")
    print(f"EAP identity: {doc.get('eap_identity')}")
    if doc.get("wan_mac"):
        print(f"WAN MAC (clone): {doc.get('wan_mac')}")
    if doc.get("vendor_class"):
        print(f"DHCP vendor class: {doc.get('vendor_class')}")
    print(f"DHCP ClientIdentifier: {doc.get('dhcp_client_identifier')}")
    if doc.get("ca_cert"):
        print(f"CA bundle: {doc.get('ca_cert')}")
    if doc.get("lightspeed_p12"):
        print(f"lightspeed_p12: {doc.get('lightspeed_p12')}")
    print(f"Output: {doc.get('out_dir')}")
    if doc.get("dry_run"):
        print("(dry-run — no files written)")
        return
    for label, path in sorted((doc.get("files") or {}).items()):
        print(f"  {label}: {path}")
    print(f"PKI material (copy to {doc.get('pki_dir')}):")
    for label, path in sorted((doc.get("pki_out_files") or doc.get("pki_files") or {}).items()):
        print(f"  {label}: {path}")


def _run_gen_network_config(args: argparse.Namespace) -> int:
    flash_path: Path | None = None
    try:
        if getattr(args, "flash_opt", None) is not None or (
            getattr(args, "operands", None) and not getattr(args, "client_pem", None)
        ):
            flash_path = _resolve_flash_path(args)
    except SystemExit:
        flash_path = None

    if flash_path is None and getattr(args, "client_pem", None) is None:
        print(
            "paceflash: gen-network-config requires --flash, a FLASH operand, or --client-pem",
            file=sys.stderr)
        return 2
    doc = gen_network_config(
        interface=getattr(args, "interface", "wan0"),
        profile="router",
        out_dir=getattr(args, "out_dir", Path("lightspeed-network")),
        ca_cert=getattr(args, "ca_cert", None),
        eapol_certs_pkgstream=getattr(args, "eapol_certs_pkgstream", None),
        client_pem=getattr(args, "client_pem", None),
        eap_identity=getattr(args, "identity", None),
        wan_mac=getattr(args, "wan_mac", None),
        clone_wan_mac=not getattr(args, "no_clone_mac", False),
        vendor_class=getattr(args, "vendor_class", None),
        firmware_version=getattr(args, "firmware_version", None),
        product_class=getattr(args, "product_class", "homeportal"),
        modem_dhcp_match=not getattr(args, "no_modem_dhcp", False),
        dhcp_client_id_override=getattr(args, "dhcp_client_id", None),
        serial=getattr(args, "serial", None),
        flash_path=flash_path,
        cert=getattr(args, "cert", "lightspeed"),
        include_p12=not getattr(args, "no_p12", False),
        dry_run=getattr(args, "dry_run", False))
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_gen_network_config_human(doc)
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
        include_p12_b64=not getattr(args, "no_p12", False))
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


def _print_board_info_human(doc: dict[str, Any]) -> None:
    print(f"Flash: {doc.get('flash')}")
    lp = doc.get("loader_partition")
    if isinstance(lp, dict):
        print(
            f"Loader MTD: offset={lp.get('offset')} size={lp.get('size')} "
            f"(index {lp.get('index')})"
        )
    ident = doc.get("identity") or {}
    if ident:
        print("Factory identity (loader MTD):")
        for k in ("model", "sn", "mac", "pca", "mfg_timestamp"):
            if ident.get(k):
                print(f"  {k}={ident[k]}")
    fac = doc.get("factory") or {}
    if not fac.get("ok"):
        print(f"Factory block: {fac.get('error', fac)}")
    pt = doc.get("paramtool_selected") or {}
    if pt:
        print("Paramtool (selected):")
        for k, v in sorted(pt.items()):
            print(f"  {k}={v}")
    if doc.get("pkgd_downgrade_policy_note"):
        print(doc["pkgd_downgrade_policy_note"])
    av = doc.get("active_version") or {}
    if av.get("ok"):
        print(
            f"Active firmware (ext2 {av.get('ext2_path')} → {av.get('runtime_path')}): "
            f"{av.get('text', '').splitlines()[0] if av.get('text') else ''}"
        )
        parsed = av.get("parsed") or {}
        fields = parsed.get("fields") or {}
        if fields:
            print(
                "  parsed: "
                f"{fields.get('n0_major')}.{fields.get('n1_minor')}."
                f"{fields.get('n2_build')}.{fields.get('n3_patch')}"
            )
            note = parsed.get("pkgd_downgrade_note")
            if note:
                print(f"  ({note})")
    else:
        print(f"Active firmware file: {av.get('error', 'not found on ext2')}")
    for vf in doc.get("version_files") or []:
        if vf.get("ok"):
            continue
        print(f"  missing: {vf.get('ext2_path')} ({vf.get('error')})")
    xc = doc.get("version_crosscheck")
    if xc:
        print(
            "CMDB vs ext2: "
            f"part1.Name={xc.get('cmdb_part1_name')!r} "
            f"ext2={xc.get('ext2_active_first_line')!r} "
            f"match={xc.get('match')}"
        )
    for block in doc.get("cmdb_ext2") or []:
        if not block.get("ok"):
            continue
        mu = block.get("mgmt_upgstate") or {}
        print(f"\nCMDB {block.get('path')} mgmt_upgstate:")
        print(f"  part1: Name={mu.get('part1_name')!r} Status={mu.get('part1_status')!r}")
        print(f"  part2: Name={mu.get('part2_name')!r} Status={mu.get('part2_status')!r}")
        if mu.get("part2_path"):
            print(f"  part2_path={mu.get('part2_path')}")
    for block in doc.get("tlpart_mgmt_upgstate") or []:
        mu = block.get("mgmt_upgstate") or {}
        print(f"\ntlpart mgmt_upgstate @{block.get('offset', 0):#x}:")
        print(f"  part1.Name={mu.get('part1_name')!r}")
    cell = doc.get("cellular") or {}
    if cell.get("imei") or cell.get("error"):
        print("\nLTE / QxDM (CMDB usim — not factory block):")
        if cell.get("imei"):
            print(f"  IMEI={cell.get('imei')}  source={cell.get('source')}")
            if doc.get("qxdm_passcode"):
                print(f"  QxDM passcode (last 6): {doc.get('qxdm_passcode')}")
        else:
            print(f"  IMEI: not found ({cell.get('error', 'unknown')})")
            print(
                "  hint: modem may be unpopulated or never synced USIM to CMDB "
                "(SIM not required for IMEI read, but module must register)"
            )
    print("\nlibboard RE (version file API):")
    bb = (doc.get("libboard_re") or {}).get("board_build_version") or {}
    for line in bb.get("offline_ext2_equivalents") or []:
        print(f"  {line}")
    for w in doc.get("warnings") or []:
        print(f"paceflash: warning: {w}", file=sys.stderr)


def _run_board_info(args: argparse.Namespace, flash_path: Path) -> int:
    doc = dump_board_info(
        flash_path,
        cmdline=_cmdline_from_args(args),
        nand_translate=not getattr(args, "no_nand_translate", False),
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        bbm_chain_aware=getattr(args, "bbm_chain_aware", False),
        redact=getattr(args, "redact", False),
        include_tlpart_scan=not getattr(args, "no_tlpart_scan", False))
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_board_info_human(doc)
    return 0 if doc.get("ok") else 1


def _run_factory_params(args: argparse.Namespace, flash_path: Path) -> int:
    nand_translate = not getattr(args, "no_nand_translate", False)
    doc = dump_factory_params(
        flash_path,
        cmdline=_cmdline_from_args(args),
        nand_translate=nand_translate,
        nand_translate_mode=getattr(args, "nand_mode", "inline-2112"),
        hint_offset=getattr(args, "offset", None),
        redact=getattr(args, "redact", False))
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
                getattr(args, "carrier_index", None)),
            probe_loader_env=getattr(args, "probe_loader_env", False),
            probe_mtdoops=getattr(args, "probe_mtdoops", False),
            mtdoops_record_size=getattr(args, "mtdoops_record_size", 131072),
            dump_opentla4_ext2=getattr(args, "dump_opentla4_ext2", None),
            extract_ext2_dir=getattr(args, "extract_ext2_dir", None),
            debug=debug)
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
        description="List or read opentla4 ext2 on a Pace flash dump; use --debug for full inventory.")
    _add_global_flash_options(ap)
    sub = ap.add_subparsers(dest="command", required=True)
    ls = sub.add_parser(
        "ls",
        help="List a directory on the TL slice ext2 volume (default /)")
    _add_global_flash_options(ls, suppress_if_unset=True)
    _add_subcommand_common_args(ls)
    _add_operands_arg(
        ls,
        metavar="[FLASH] [PATH]",
        help_text=(
            "With --flash: ext2 directory (default /). Otherwise: flash dump path, then optional ext2 path"
        ))
    ls.add_argument("-a", "--all", action="store_true", help="Include . and .. entries")
    ls.add_argument("-l", "--long", action="store_true", help="Long listing (mode + name)")
    ls.add_argument("--json", action="store_true", help="JSON directory listing, or full inventory with --debug")
    ls.add_argument(
        "--debug",
        action="store_true",
        help="Full flash inventory (MTD, BBM, TL, UBI) instead of a single-directory listing")
    ls.add_argument("--no-ext2", action="store_true", help="With --debug: skip ext2 carve")
    ls.add_argument(
        "--no-squashfs",
        action="store_true",
        help="With --debug: skip embedded SquashFS probes in ext2")
    ls.add_argument(
        "--ubi-erase-bytes",
        type=int,
        default=131072,
        metavar="N",
        help="With --debug: PEB erase size for UBI VID scan (default 131072)")
    ls.add_argument(
        "--tl-probe-report",
        action="store_true",
        help="With --debug: emit TLDiskProbeReport on TL enumeration failure")
    ls.add_argument(
        "--dump-tl-slice",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Write raw TL child partition bytes for --tl-slice to PATH (SquashFS magic may not be at offset 0)"
        ))
    ls.add_argument(
        "--dump-opentla4-ext2",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Write assembled opentla4 ext2 partition image (same bytes as --dump-tl-slice when "
            "--tl-slice opentla4); use debugfs/e2tools on the output"
        ))
    ls.add_argument(
        "--extract-ext2-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Extract sys1/rootimage.img, sys2/rootimage.img, etc. from opentla4 ext2 into DIR "
            "(writes manifest.json with sizes and strict squash SHA when applicable)"
        ))
    ls.add_argument(
        "--lib2spy-json",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "lib2spy verify JSON for carrier squash FILE fingerprints; enables upgrade_nand_correlation "
            "and anchored SquashFS dissect/carve on TL views"
        ))
    ls.add_argument(
        "--pkgstream",
        type=Path,
        default=None,
        metavar="PATH",
        help="Optional .pkgstream path to compute SHA-256 carrier refs (with --lib2spy-json)")
    ls.add_argument(
        "--firmware-collection",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Device firmware tree (e.g. firmware/00D09E): correlate NAND against every install "
            ".pkgstream under DIR (rootimage.img + ui.img). Overrides --lib2spy-json when set."
        ))
    ls.add_argument(
        "--carrier-index",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Prebuilt carrier digest JSON from `paceflash build-carrier-index` "
            f"(default tries {_DEFAULT_CARRIER_INDEX} when using --firmware-collection)"
        ))
    ls.add_argument(
        "--probe-loader-env",
        action="store_true",
        help="Parse U-Boot env v1 at loader MTD base (linear slice; bootcmd/mtdparts)")
    ls.add_argument(
        "--probe-mtdoops",
        action="store_true",
        help="Scan mtdoops MTD slice for panic/oops records (linear; default record_size 131072)")
    ls.add_argument(
        "--mtdoops-record-size",
        type=int,
        default=131072,
        metavar="N",
        help="mtdoops record_size for --probe-mtdoops (default 131072 per fwupgrade cmdline)")

    sh = sub.add_parser(
        "shell",
        help="Interactive ext2 shell (flash loaded once; ls, cd, cat, pwd)")
    _add_global_flash_options(sh, suppress_if_unset=True)
    _add_subcommand_common_args(sh)
    _add_operands_arg(
        sh,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash before shell)")
    sh.add_argument(
        "-c",
        "--command",
        dest="shell_command",
        metavar="CMD",
        help="Run one shell command and exit (non-interactive)")

    cat = sub.add_parser("cat", help="Print a regular file from the TL slice ext2 volume")
    cat.add_argument(
        "--output",
        "-o",
        type=Path,
        metavar="FILE",
        help="Write file bytes to FILE instead of stdout (avoids PowerShell text redirect)")
    _add_global_flash_options(cat, suppress_if_unset=True)
    _add_subcommand_common_args(cat)
    _add_operands_arg(
        cat,
        metavar="[FLASH] PATH",
        help_text=(
            "With --flash: ext2 file path. Otherwise: flash dump path then ext2 file path"
        ))

    ha = sub.add_parser(
        "dump-http-auth",
        help="Dump httpd auth realms map, factory access codes, and CMDB user passwords")
    _add_global_flash_options(ha, suppress_if_unset=True)
    _add_nand_args(ha)
    _add_operands_arg(
        ha,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)")
    ha.add_argument(
        "--redact",
        action="store_true",
        help="Mask accesscode/Wi‑Fi/CM password fields in output")
    ha.add_argument(
        "--decode-hashes",
        action="store_true",
        help="Include hex of base64 CM password blobs (lab only)")
    ha.add_argument(
        "--no-tlpart-scan",
        action="store_true",
        help="Skip scanning assembled tlpart for embedded CM user tables")
    ha.add_argument("--json", action="store_true")

    cf = sub.add_parser(
        "dump-cmdb-fw",
        help="Dump CMDB firewall state: pinholes (hostapps), fw params, and rule tables")
    _add_global_flash_options(cf, suppress_if_unset=True)
    _add_nand_args(cf)
    _add_operands_arg(
        cf,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH or --cmdb PATH)")
    cf.add_argument(
        "--cmdb",
        type=Path,
        default=None,
        metavar="PATH",
        help="Read CMDB XML from a local cmlegacy.* file instead of flash ext2")
    cf.add_argument(
        "--tables",
        type=str,
        default=None,
        help="Comma-separated CM table names to parse (default: firewall/pinhole set)")
    cf.add_argument(
        "--catalog",
        action="store_true",
        help="Include full apps/ports catalog in JSON output")
    cf.add_argument(
        "--pinholes-only",
        action="store_true",
        help="Human output: pinholes section only")
    cf.add_argument(
        "--no-tlpart-scan",
        action="store_true",
        help="Skip scanning assembled tlpart for embedded CMDB firewall chunks")
    cf.add_argument("--json", action="store_true")

    lt = sub.add_parser(
        "cmdb-list-tables",
        help="List CMDB table names in a local cmlegacy.* XML file")
    lt.add_argument("--cmdb", type=Path, required=True, metavar="PATH")
    lt.add_argument("--json", action="store_true")

    eap = sub.add_parser(
        "dump-eapol-cert",
        help="Extract lightspeed/device PKCS#12 from assembled tlpart and decrypt to PEM")
    _add_global_flash_options(eap, suppress_if_unset=True)
    _add_nand_args(eap)
    _add_operands_arg(
        eap,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)")
    eap.add_argument(
        "--cert",
        choices=("lightspeed", "device"),
        default="lightspeed",
        help="Which *_p12= blob to extract (default lightspeed / WAN EAPOL)")
    eap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write decrypted PEM to FILE (default ./{cert}_{CN}_eapol.pem from cert subject)")
    eap.add_argument(
        "--p12",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write raw PKCS#12 to FILE (default ./{cert}_{CN}.p12 from cert subject)")
    eap.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Only extract and write PKCS#12 from flash (no cryptography / PEM)")
    eap.add_argument(
        "--stdout-pem",
        action="store_true",
        help="Write decrypted PEM to stdout instead of -o")
    eap.add_argument(
        "--redact",
        action="store_true",
        help="Omit devkey/password from --json (safe for logs)")
    eap.add_argument("--json", action="store_true")

    _gnc_epilog = """
examples:
  %(prog)s "PACE 5268AC S34ML01G1@TSOP48.BIN"
  %(prog)s "PACE ...BIN" --out-dir ./lightspeed-network --interface wan0
  %(prog)s "PACE ...BIN" --wan-mac d4:b2:7a:6b:b1:4c --firmware-version "11.14.1.123456"
  %(prog)s --client-pem ./lightspeed_eapol.pem --serial 38161N043704

writes (under --out-dir):
  pki/lightspeed.p12, lightspeed_eapol.pem, cacerts.pem, client.pem, client.key
  wpa_supplicant-<iface>.conf, <iface>.network, wpa_supplicant@<iface>.service.d/, README.md

from flash: dump-eapol-cert (lightspeed_p12), auto CA from eapol-certs pkgstream.
DHCP (default): ClientIdentifier 00D09E-{sn}, MACAddress clone, VendorClassIdentifier
2WHPL M.m.b, RequestOptions + max message size. Option 125 notes in README.
See reference/linux_8021x_lightspeed.md.
""".strip()
    gnc = sub.add_parser(
        "gen-network-config",
        help="802.1X router bundle: wpa_supplicant + systemd-networkd + PKI + DHCP parity",
        description=(
            "Generate wpa_supplicant and systemd-networkd files for Lightspeed WAN "
            "EAP-TLS (router profile). With a flash dump, extracts and decrypts "
            "lightspeed_p12, resolves operator CA, and emits modem-like DHCP options."
        ),
        epilog=_gnc_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_global_flash_options(gnc, suppress_if_unset=True)
    _add_nand_args(gnc)
    _add_operands_arg(
        gnc,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)")
    gnc.add_argument(
        "--interface",
        default="wan0",
        help="Linux WAN interface name (default wan0)")
    gnc.add_argument(
        "--out-dir",
        type=Path,
        default=Path("lightspeed-network"),
        metavar="DIR",
        help="Output directory for configs and pki/ subtree (default ./lightspeed-network)")
    gnc.add_argument(
        "--ca-cert",
        type=Path,
        default=None,
        metavar="FILE",
        help="Operator CA bundle PEM (default: extracted prod bundle or --eapol-certs-pkgstream)")
    gnc.add_argument(
        "--eapol-certs-pkgstream",
        type=Path,
        default=None,
        metavar="FILE",
        help="att_unified_eapol-certs.pkgstream (extracted if CA PEM not already present)")
    gnc.add_argument(
        "--client-pem",
        type=Path,
        default=None,
        metavar="FILE",
        help="Decrypted client PEM (instead of --flash + dump-eapol-cert)")
    gnc.add_argument(
        "--identity",
        default=None,
        help="EAP-TLS identity override (default: cert subject CN / MAC)")
    gnc.add_argument(
        "--wan-mac",
        default=None,
        metavar="MAC",
        help="WAN MAC override for [Link] MACAddress (default: cert CN or factory mac=)")
    gnc.add_argument(
        "--no-clone-mac",
        action="store_true",
        help="Do not set MACAddress in the .network file")
    gnc.add_argument(
        "--vendor-class",
        default=None,
        metavar="STRING",
        help='DHCP option 60 (default: derive "2WHPL M.m.b" from --firmware-version)')
    gnc.add_argument(
        "--firmware-version",
        default=None,
        metavar="TEXT",
        help='Dotted build string for vendor class (e.g. "11.14.1.123456" -> 2WHPL 11.14.1)')
    gnc.add_argument(
        "--product-class",
        default="homeportal",
        help="TR-069 ProductClass for README / option 125 notes (default homeportal)")
    gnc.add_argument(
        "--no-modem-dhcp",
        action="store_true",
        help="Omit modem-like RequestOptions / max-message-size / vendor class from .network")
    gnc.add_argument(
        "--dhcp-client-id",
        default=None,
        metavar="ID",
        help="DHCP ClientIdentifier override (default 00D09E-{factory sn})")
    gnc.add_argument(
        "--serial",
        default=None,
        help="Factory serial when using --client-pem without --flash")
    gnc.add_argument(
        "--cert",
        choices=("lightspeed", "device"),
        default="lightspeed",
        help="PKCS#12 name when extracting from flash (default lightspeed / lightspeed_p12)")
    gnc.add_argument(
        "--no-p12",
        action="store_true",
        help="Do not write pki/lightspeed.p12 (PEM split only)")
    gnc.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan outputs only; do not write files")
    gnc.add_argument("--json", action="store_true")

    fp = sub.add_parser(
        "factory-params",
        help="Dump factory manufacturing key=value block from loader MTD (sn, mac, …)")
    _add_global_flash_options(fp, suppress_if_unset=True)
    _add_nand_args(fp)
    _add_operands_arg(
        fp,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)")
    fp.add_argument(
        "--offset",
        type=lambda x: int(x, 0),
        default=None,
        metavar="OFF",
        help=f"Hint offset of model= in loader (default auto; PACE ~{0x1FF84:#x})")
    fp.add_argument(
        "--redact",
        action="store_true",
        help="Mask devkey/authcode/wifi secrets in output (safe for logs)")
    fp.add_argument("--json", action="store_true")

    pt = sub.add_parser(
        "paramtool",
        help="Dump board_param / paramtool keys (gw:*) from assembled tlpart (offline RE)")
    _add_global_flash_options(pt, suppress_if_unset=True)
    _add_nand_args(pt)
    _add_operands_arg(
        pt,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)")
    pt.add_argument(
        "--get",
        metavar="KEY",
        default=None,
        help="Get one key (e.g. gw:trust_engcert); default is --show all keys found")
    pt.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="With --get: write value to FILE (mirrors paramtool -get NAME -out FILE)")
    pt.add_argument(
        "--no-p12",
        action="store_true",
        help="Omit *_p12 base64 blobs from listing (gw:* keys only)")
    pt.add_argument(
        "--redact",
        action="store_true",
        help="Mask *_p12 and other sensitive values")
    pt.add_argument("--json", action="store_true")

    bi = sub.add_parser(
        "board-info",
        help="Dump factory identity, paramtool keys, ext2 version files, CMDB upgrade state")
    _add_global_flash_options(bi, suppress_if_unset=True)
    _add_nand_args(bi)
    _add_operands_arg(
        bi,
        metavar="[FLASH]",
        help_text="Flash dump (optional when using --flash PATH)")
    bi.add_argument(
        "--redact",
        action="store_true",
        help="Mask factory secrets in output (safe for logs)")
    bi.add_argument(
        "--no-tlpart-scan",
        action="store_true",
        help="Skip embedded mgmt_upgstate scan in assembled tlpart")
    bi.add_argument("--json", action="store_true")

    bci = sub.add_parser(
        "build-carrier-index",
        help="Precompute rootimage/ui squash SHA-256 refs for all 00D09E install pkgstreams")
    bci.add_argument(
        "firmware_collection",
        type=Path,
        metavar="DIR",
        help="Firmware device tree root (e.g. …/firmware/00D09E)")
    bci.add_argument(
        "--out",
        type=Path,
        default=_DEFAULT_CARRIER_INDEX,
        metavar="PATH",
        help=f"Output JSON cache path (default {_DEFAULT_CARRIER_INDEX})")

    pte = sub.add_parser(
        "patch-trust-engcert",
        help="Patch gw:trust_engcert in board_param env copies (immutable: writes new flash file)")
    _add_global_flash_options(pte, suppress_if_unset=True)
    _add_operands_arg(
        pte,
        metavar="[FLASH]",
        help_text="Source flash dump (optional when using --flash PATH)")
    pte.add_argument(
        "--value",
        choices=("true", "false"),
        default="true",
        help="trust_engcert value (default: true)")
    pte.add_argument(
        "--out",
        type=Path,
        required=True,
        metavar="FILE",
        help="Output flash dump path (original is never modified)")
    pte.add_argument(
        "--manifest",
        type=Path,
        default=None,
        metavar="JSON",
        help="Patch manifest JSON path (default: OUT.patch.json)")
    pte.add_argument("--json", action="store_true")

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
                indent=2)
        )
        return 0

    if args.command == "ls":
        flash_path, ext2_path = _resolve_flash_and_path_operands(args, require_path=False)
        if (
            getattr(args, "debug", False)
            or getattr(args, "no_ext2", False)
            or getattr(args, "dump_tl_slice", None) is not None
            or getattr(args, "no_nand_translate", False)
        ):
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

    if args.command == "dump-cmdb-fw":
        flash_path = None
        if getattr(args, "cmdb", None) is None:
            flash_path = _resolve_flash_path(args)
        return _run_dump_cmdb_fw(args, flash_path)

    if args.command == "cmdb-list-tables":
        return _run_cmdb_list_tables(args)

    if args.command == "dump-eapol-cert":
        flash_path = _resolve_flash_path(args)
        return _run_dump_eapol_cert(args, flash_path)

    if args.command == "gen-network-config":
        return _run_gen_network_config(args)

    if args.command == "factory-params":
        flash_path = _resolve_flash_path(args)
        return _run_factory_params(args, flash_path)

    if args.command == "paramtool":
        flash_path = _resolve_flash_path(args)
        return _run_paramtool(args, flash_path)

    if args.command == "board-info":
        flash_path = _resolve_flash_path(args)
        return _run_board_info(args, flash_path)

    if args.command == "patch-trust-engcert":
        flash_path = _resolve_flash_path(args)
        manifest = args.manifest
        if manifest is None:
            manifest = Path(str(args.out) + ".patch.json")
        doc = patch_trust_engcert_flash(
            flash_path,
            value=args.value,
            out_path=args.out,
            manifest_path=manifest)
        if args.json:
            print(json.dumps(doc, indent=2))
        else:
            print(f"Wrote {args.out}")
            print(f"Manifest {manifest}")
            te = doc.get("patch") or {}
            print(f"Patched {te.get('site_count', 0)} env site(s); keys: {te.get('keys_changed')}")
        return 0

    return 2
