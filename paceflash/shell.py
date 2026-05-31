"""
Interactive ext2 shell on a loaded Pace flash dump (one NAND translate + mount per session).

Commands: ``ls``, ``cat``, ``cd``, ``pwd``, ``help``, ``exit`` / ``quit``.
"""

from __future__ import annotations

import shlex
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TextIO

_SHELL_COMMANDS = ("ls", "cd", "cat", "ext2map", "pwd", "help", "?", "exit", "quit")
_LS_FLAGS = ("-a", "--all", "-l", "--long")

from boardfs import (
    apply_chain_aware_virtual_tl_scan,
    assemble_opentla4_volume,
    temporary_registry_from_physical_nand)
from boardfs.ext2_dissect import resolve_mountable_ext2_superblock_offset
from boardfs.ext2_path import (
    Ext2DirectoryOpaqueError,
    ext2_file_map_report_for_path,
    list_ext2_directory,
    read_ext2_regular_file)
from opentl.driver import TranslateMode

from paceflash.flash_session import (
    Opentla4Ext2Volume,
    _apply_chain_aware_bbm_if_needed,
    _opentla4_volume_access)


@dataclass
class ShellConfig:
    flash_path: Path
    cmdline: str | None = None
    tl_slice: str = "opentla4"
    nand_translate: bool = True
    nand_translate_mode: TranslateMode = "inline-2112"
    bbm_chain_aware: bool = False


def _normalize_posix_parts(parts: tuple[str, ...]) -> str:
    stack: list[str] = []
    for part in parts:
        if part in ("/", ""):
            continue
        if part == ".":
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)
    return "/".join(stack)


def resolve_ext2_cwd(cwd: str, user_path: str) -> str:
    """Resolve ``user_path`` against ext2 cwd (POSIX semantics); return path relative to volume root."""
    raw = user_path.strip()
    if not raw:
        return cwd
    if raw.startswith("/"):
        combined = PurePosixPath("/") / raw.lstrip("/")
    elif cwd:
        combined = PurePosixPath("/") / cwd / raw
    else:
        combined = PurePosixPath("/") / raw
    return _normalize_posix_parts(combined.parts)


def display_path(cwd: str) -> str:
    return "/" if not cwd else f"/{cwd}"


class Ext2ShellSession:
    """Mounted opentla4 ext2 kept in memory for repeated ``ls`` / ``cat`` / ``cd``."""

    def __init__(
        self,
        config: ShellConfig,
        vol: Opentla4Ext2Volume,
        *,
        _registry_ctx: Any = None) -> None:
        self.config = config
        self.vol = vol
        self.cwd: str = ""
        self._registry_ctx = _registry_ctx

    def close(self) -> None:
        ctx = self._registry_ctx
        if ctx is not None:
            ctx.__exit__(None, None, None)
            self._registry_ctx = None

    @classmethod
    def open(cls, config: ShellConfig) -> Ext2ShellSession:
        from typing import Any

        line = config.cmdline
        if line is None:
            from unand.mtd import DEFAULT_MTDPARTS

            line = f"quiet rw {DEFAULT_MTDPARTS}"
        ctx = temporary_registry_from_physical_nand(
            config.flash_path,
            line,
            translate_mode=config.nand_translate_mode)
        reg, man, ot = ctx.__enter__()
        _apply_chain_aware_bbm_if_needed(
            reg, man, ot, bbm_chain_aware=config.bbm_chain_aware, tl_slice=config.tl_slice
        )
        assembled = assemble_opentla4_volume(reg, slice_name=config.tl_slice, lazy_assembly=True)
        if not assembled.slice_bytes:
            ctx.__exit__(None, None, None)
            raise RuntimeError(assembled.error or "no opentla4 slice bytes assembled")
        sb = assembled.ext2_sb_offset
        if sb is None:
            sb = resolve_mountable_ext2_superblock_offset(assembled.slice_bytes)
        if sb is None:
            ctx.__exit__(None, None, None)
            raise RuntimeError(assembled.error or "no mountable ext2 on opentla4 slice")
        vol = Opentla4Ext2Volume(
            slice_bytes=assembled.slice_bytes,
            sb_off=sb,
            read_model=assembled.read_model,
            slice_name=config.tl_slice,
            access=_opentla4_volume_access(reg, assembled, slice_name=config.tl_slice))
        return cls(config, vol, _registry_ctx=ctx)

    def _resolve(self, user_path: str) -> str:
        return resolve_ext2_cwd(self.cwd, user_path)

    def list_dir_names(
        self,
        rel_dir: str,
        *,
        dirs_only: bool = False) -> list[tuple[str, str]]:
        """Return ``(name, kind)`` entries under ``rel_dir`` (volume-relative)."""
        try:
            rows = list_ext2_directory(
                self.vol.slice_bytes,
                rel_dir,
                sb_off=self.vol.sb_off,
                access=self.vol.access)
        except (NotADirectoryError, FileNotFoundError):
            return []
        except (OSError, ValueError, Ext2DirectoryOpaqueError):
            return []
        out: list[tuple[str, str]] = []
        for row in rows:
            kind = str(row.get("kind", "other"))
            if dirs_only and kind != "dir":
                continue
            name = str(row.get("name", ""))
            if name and name not in (".", ".."):
                out.append((name, kind))
        return out

    def path_completions(self, partial: str, *, dirs_only: bool) -> list[str]:
        """
        Completions for a single path token (readline ``text``); each match starts with ``partial``.
        """
        if not partial:
            dir_rel = self.cwd
            tail = ""
            head = ""
        elif "/" in partial:
            idx = partial.rfind("/")
            head = partial[: idx + 1]
            tail = partial[idx + 1 :]
            dir_rel = self._resolve(head.rstrip("/") or ".")
        else:
            head = ""
            tail = partial
            dir_rel = self.cwd

        matches: list[str] = []
        for name, kind in self.list_dir_names(dir_rel, dirs_only=dirs_only):
            if not name.startswith(tail):
                continue
            full = f"{head}{name}"
            if kind == "dir":
                full += "/"
            matches.append(full)
        return sorted(matches, key=lambda s: (s.endswith("/"), s.lower()))

    def line_completions(
        self,
        line: str,
        text: str,
        *,
        prefix_end: int | None = None) -> list[str]:
        """All completion strings for the active token (each must start with ``text``)."""
        if prefix_end is None:
            try:
                import readline

                prefix_end = readline.get_begidx()
            except ImportError:
                prefix_end = max(0, len(line) - len(text))

        prefix = line[:prefix_end]
        if not prefix.strip():
            return [c for c in _SHELL_COMMANDS if c.startswith(text)]
        if " " not in prefix.rstrip():
            return [c for c in _SHELL_COMMANDS if c.startswith(text)]

        try:
            tokens = shlex.split(prefix, posix=True)
        except ValueError:
            tokens = prefix.strip().split()

        cmd = tokens[0] if tokens else ""
        if cmd == "ls":
            if text.startswith("-") or text in _LS_FLAGS:
                return [f for f in _LS_FLAGS if f.startswith(text)]
            return self.path_completions(text, dirs_only=False)
        if cmd == "cd":
            return self.path_completions(text, dirs_only=True)
        if cmd == "cat":
            return self.path_completions(text, dirs_only=False)
        return []

    def cmd_pwd(self) -> int:
        print(display_path(self.cwd))
        return 0

    def cmd_cd(self, argv: list[str]) -> int:
        if len(argv) > 1:
            print("paceflash: usage: cd [PATH]", file=sys.stderr)
            return 1
        target = self._resolve(argv[0] if len(argv) == 1 else ".")
        try:
            list_ext2_directory(
                self.vol.slice_bytes,
                target,
                sb_off=self.vol.sb_off,
                cap=1,
                access=self.vol.access)
        except NotADirectoryError:
            print(f"paceflash: not a directory: {display_path(target)}", file=sys.stderr)
            return 1
        except (FileNotFoundError, OSError) as e:
            print(f"paceflash: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        self.cwd = target
        return 0

    def cmd_ls(self, argv: list[str]) -> int:
        show_all = False
        long_fmt = False
        paths: list[str] = []
        i = 0
        while i < len(argv):
            a = argv[i]
            if a in ("-a", "--all"):
                show_all = True
                i += 1
                continue
            if a in ("-l", "--long"):
                long_fmt = True
                i += 1
                continue
            if a.startswith("-"):
                print(f"paceflash: ls: unknown option: {a}", file=sys.stderr)
                return 1
            paths.append(a)
            i += 1
        if not paths:
            paths = ["."]
        exit_code = 0
        for p in paths:
            rel = self._resolve(p)
            try:
                rows = list_ext2_directory(
                    self.vol.slice_bytes,
                    rel,
                    sb_off=self.vol.sb_off,
                    include_dot=show_all,
                    access=self.vol.access,
                )
            except NotADirectoryError:
                print(f"paceflash: not a directory: {display_path(rel)}", file=sys.stderr)
                exit_code = 1
                continue
            except Ext2DirectoryOpaqueError as e:
                print(f"paceflash: {e}", file=sys.stderr)
                exit_code = 1
                continue
            except (FileNotFoundError, OSError) as e:
                print(f"paceflash: {type(e).__name__}: {e}", file=sys.stderr)
                exit_code = 1
                continue
            if len(paths) > 1:
                print(f"{display_path(rel)}:")
            for row in rows:
                if long_fmt:
                    print(f"{row.get('file_type', '?'):>10}  {row.get('name', '')}")
                else:
                    print(row.get("name", ""))
        return exit_code

    def cmd_cat(self, argv: list[str]) -> int:
        paths: list[str] = []
        for a in argv:
            if a.startswith("-"):
                print(f"paceflash: cat: unknown option: {a}", file=sys.stderr)
                return 1
            paths.append(a)
        if len(paths) != 1:
            print("paceflash: usage: cat PATH", file=sys.stderr)
            return 1
        rel = self._resolve(paths[0])
        try:
            data = read_ext2_regular_file(
                self.vol.slice_bytes,
                rel,
                sb_off=self.vol.sb_off,
                access=self.vol.access,
            )
        except IsADirectoryError:
            print(f"paceflash: is a directory: {display_path(rel)}", file=sys.stderr)
            return 1
        except EOFError as e:
            print(
                f"paceflash: ext2 read failed for {display_path(rel)}: {e}",
                file=sys.stderr)
            return 1
        except (FileNotFoundError, OSError) as e:
            print(f"paceflash: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        sys.stdout.buffer.write(data)
        return 0

    def cmd_ext2map(self, argv: list[str]) -> int:
        max_blocks = 64
        paths: list[str] = []
        i = 0
        while i < len(argv):
            if argv[i] in ("-n", "--max-blocks") and i + 1 < len(argv):
                max_blocks = max(1, int(argv[i + 1], 0))
                i += 2
                continue
            paths.append(argv[i])
            i += 1
        if len(paths) != 1:
            print(
                "paceflash: usage: ext2map [-n N] PATH",
                file=sys.stderr)
            return 1
        rel = self._resolve(paths[0])
        try:
            lines = ext2_file_map_report_for_path(
                self.vol.slice_bytes,
                rel,
                sb_off=self.vol.sb_off,
                max_blocks=max_blocks)
        except IsADirectoryError:
            print(f"paceflash: is a directory: {display_path(rel)}", file=sys.stderr)
            return 1
        except (FileNotFoundError, OSError, ValueError) as e:
            print(f"paceflash: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        for line in lines:
            print(line)
        return 0

    def cmd_help(self, _argv: list[str]) -> int:
        print(
            """Built-in commands (ext2 on opentla4):
  ls [-a] [-l] [PATH...]   list directory (default .)
  cd [PATH]                change directory (default .)
  pwd                      print working directory
  cat PATH                 read file (PACE capture read: shadow promote + stale extent recovery)
  ext2map [-n N] PATH      kernel-aligned ext2 block map (inode vs file blocks)
  help                     this message
  exit, quit               leave the shell"""
        )
        return 0

    def run_argv(self, argv: list[str]) -> int:
        if not argv:
            return 0
        cmd = argv[0]
        rest = argv[1:]
        handlers = {
            "ls": self.cmd_ls,
            "cd": self.cmd_cd,
            "cat": self.cmd_cat,
            "ext2map": self.cmd_ext2map,
            "pwd": lambda _: self.cmd_pwd(),
            "help": self.cmd_help,
            "?": self.cmd_help,
        }
        if cmd in ("exit", "quit"):
            raise SystemExit(0)
        fn = handlers.get(cmd)
        if fn is None:
            print(f"paceflash: unknown command: {cmd!r} (try help)", file=sys.stderr)
            return 1
        return fn(rest)

    def run_line(self, line: str) -> int:
        line = line.strip()
        if not line or line.startswith("#"):
            return 0
        try:
            argv = shlex.split(line, posix=True)
        except ValueError as e:
            print(f"paceflash: {e}", file=sys.stderr)
            return 1
        try:
            return self.run_argv(argv)
        except SystemExit:
            raise
        except Exception as e:
            print(f"paceflash: {type(e).__name__}: {e}", file=sys.stderr)
            return 1


_SHELL_HELP = """\
paceflash ext2 shell — flash stays loaded; use ls, cd, cat, pwd.
Type help for commands, exit to quit. Tab completes commands and paths.
"""


def setup_readline_completion(session: Ext2ShellSession) -> bool:
    """
    Install readline tab completion for an interactive session.

    Returns True when readline was configured, False when the module is missing.

    On Windows, install the optional extra: ``pip install -e ".[shell]"`` (pulls pyreadline3).
    On Linux/macOS, CPython usually ships ``readline`` in the stdlib when linked against libreadline.
    """
    try:
        import readline
    except ImportError:
        if sys.platform == "win32":
            print(
                "paceflash: tab completion unavailable (install pyreadline3: "
                'pip install -e ".[shell]" or pip install pyreadline3)',
                file=sys.stderr)
        return False

    cache: list[str] = []

    def completer(text: str, state: int) -> str | None:
        if state == 0:
            line = readline.get_line_buffer()
            cache[:] = session.line_completions(line, text)
        return cache[state] if state < len(cache) else None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    # Keep ``/`` in path tokens so ``sys1/<Tab>`` completes inside the directory.
    readline.set_completer_delims(" \t\n")
    if hasattr(readline, "set_history_length"):
        readline.set_history_length(500)
    return True


def run_interactive(
    session: Ext2ShellSession,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    cfg = session.config
    print(
        f"paceflash: {cfg.flash_path} slice={session.vol.slice_name!r} "
        f"read_model={session.vol.read_model!r}",
        file=sys.stderr)
    print(_SHELL_HELP, file=stdout)

    readline_enabled = False
    if stdin.isatty():
        readline_enabled = setup_readline_completion(session)
        if not readline_enabled and sys.platform != "win32":
            print(
                "paceflash: tab completion unavailable (Python built without readline support)",
                file=sys.stderr)

    try:
        while True:
            try:
                prompt = f"paceflash:{display_path(session.cwd)}$ "
                if stdin.isatty():
                    line = input(prompt)
                else:
                    line = stdin.readline()
                    if line == "":
                        break
                    stdout.write(prompt)
                    stdout.write(line)
            except (EOFError, KeyboardInterrupt):
                print(file=stdout)
                break
            try:
                session.run_line(line)
            except SystemExit:
                break
    finally:
        session.close()
    return 0


def run_script(session: Ext2ShellSession, lines: list[str]) -> int:
    code = 0
    for line in lines:
        try:
            line_code = session.run_line(line)
            if line_code != 0:
                code = line_code
        except SystemExit:
            break
    session.close()
    return code
