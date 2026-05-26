"""Generate Linux router configs (wpa_supplicant + systemd-networkd) for Lightspeed WAN 802.1X."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from tr069.paths import CONNREQ_OUI

# Subject CN regex mirrored from paceflash.eapol_cert (avoid heavy imports at load)
_SUBJECT_CN_RE = re.compile(r"CN=([^,]+)", re.IGNORECASE)
_MAC_COLON_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_MAC_HEX12_RE = re.compile(r"^[0-9A-Fa-f]{12}$")

CertKind = Literal["lightspeed", "device"]

Profile = Literal["router"]

_DEFAULT_PKI_DIR = Path("/etc/pki/eapol")
_WPA_CTRL = "/run/wpa_supplicant"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_EAPOL_CERTS_PKGSTREAM = (
    _REPO_ROOT
    / "firmware_11.5.1.532678/11.5.1.532678/eapol_certs/att_unified_eapol-certs.pkgstream"
)

# Observed on modem WAN DHCP REQUEST (lmd / lm_mdhcp); see reference/linux_8021x_lightspeed.md
_MODEM_DHCP_REQUEST_OPTIONS = (
    "1 2 3 6 15 42 44 46 47 23 24 25 26 35 36 119 121 249 212"
)
_DEFAULT_DHCP_MAX_MESSAGE_SIZE = 1500
_BBF_DHCP_ENTERPRISE = 3561
_TWOWIRE_DHCP_ENTERPRISE = 4839


def dhcp_client_id(serial: str | None, *, oui: str = CONNREQ_OUI) -> str | None:
    """Compose CMDB ``dhcpc clientid`` (option 61 string): ``{OUI}-{sn}``."""
    if not serial or not str(serial).strip():
        return None
    sn = str(serial).strip()
    prefix = oui.strip().upper()
    if sn.upper().startswith(f"{prefix}-"):
        return sn
    return f"{prefix}-{sn}"


def eap_identity_from_subject(subject: str | None) -> str | None:
    """Default EAP-TLS identity: certificate CN (often WAN MAC with colons)."""
    if not subject:
        return None
    m = _SUBJECT_CN_RE.search(subject)
    return m.group(1).strip() if m else None


def normalize_mac_address(value: str | None) -> str | None:
    """Return ``AA:BB:CC:DD:EE:FF`` or ``None`` if *value* is not a MAC."""
    if not value or not str(value).strip():
        return None
    s = str(value).strip()
    if _MAC_COLON_RE.match(s):
        return s.upper()
    compact = re.sub(r"[-:\s.]", "", s)
    if len(compact) == 12 and _MAC_HEX12_RE.match(compact):
        compact = compact.upper()
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    return None


def vendor_class_identifier(version_text: str | None) -> str | None:
    """
    Build option-60 string ``2WHPL M.m.b`` from ``board_build_version`` / ``board_build_digits``.

    Uses the first three dotted fields (same as ``lmd`` rodata ``"2WHPL %d.%d.%d"`` @ 0x004911b4).
    """
    if not version_text or not str(version_text).strip():
        return None
    line = str(version_text).strip().splitlines()[0].strip()
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", line)
    if not m:
        return None
    return f"2WHPL {m.group(1)}.{m.group(2)}.{m.group(3)}"


def resolve_wan_mac(
    wan_mac: str | None = None,
    *,
    identity: str | None = None,
    flash_path: str | Path | None = None,
) -> str | None:
    """WAN Ethernet MAC for DHCP **chaddr** cloning (cert CN, factory block, or override)."""
    mac = normalize_mac_address(wan_mac)
    if mac:
        return mac
    mac = normalize_mac_address(identity)
    if mac:
        return mac
    if flash_path is not None:
        from paceflash.factory_params import dump_factory_params

        fp = dump_factory_params(flash_path)
        factory = fp.get("factory") or {}
        if factory.get("ok") and isinstance(factory.get("params"), dict):
            raw = factory["params"].get("mac")
            if isinstance(raw, str):
                return normalize_mac_address(raw)
    return None


def resolve_ca_cert(
    ca_cert: Path | str | None = None,
    *,
    eapol_certs_pkgstream: Path | str | None = None,
    use_test_ca: bool = False,
) -> Path:
    """
    Resolve operator CA PEM: explicit path, pre-extracted prod bundle, or extract pkgstream.
    """
    if ca_cert is not None:
        path = Path(ca_cert).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"ca_cert not found: {path}")
        return path

    name = "lightspeed-test-cacerts.pem" if use_test_ca else "lightspeed-prod-cacerts.pem"
    extracted_root = (
        _REPO_ROOT / "firmware_11.5.1.532678/11.5.1.532678/eapol_certs/extracted"
    )
    hit = extracted_root / "etc/pki/eapol" / name
    if hit.is_file():
        return hit.resolve()

    pkg = Path(eapol_certs_pkgstream or _DEFAULT_EAPOL_CERTS_PKGSTREAM).expanduser()
    if not pkg.is_file():
        raise FileNotFoundError(
            f"no CA PEM found and pkgstream missing: {pkg} "
            f"(pass --ca-cert or extract with lib2spy --extract)"
        )

    from lib2spy.pkgstream import extract_payloads

    extract_payloads(pkg, extracted_root)
    hit = extracted_root / "etc/pki/eapol" / name
    if not hit.is_file():
        raise FileNotFoundError(
            f"extracted pkgstream but CA not at expected path: {hit}"
        )
    return hit.resolve()


def split_pem_bundle(pem: bytes) -> tuple[bytes, bytes]:
    """Split combined PEM into (certificate PEM, private key PEM)."""
    cert_blocks: list[bytes] = []
    key_blocks: list[bytes] = []
    for block in re.findall(
        rb"-----BEGIN [^-]+-----.*?-----END [^-]+-----\r?\n?",
        pem,
        flags=re.DOTALL,
    ):
        if b"PRIVATE KEY" in block:
            key_blocks.append(block)
        elif b"CERTIFICATE" in block:
            cert_blocks.append(block)
    if not key_blocks:
        raise ValueError("no private key block in PEM bundle")
    if not cert_blocks:
        raise ValueError("no certificate block in PEM bundle")
    return b"".join(cert_blocks), b"".join(key_blocks)


def render_wpa_supplicant_conf(
    *,
    interface: str,
    identity: str,
    ca_cert: Path,
    client_cert: Path,
    private_key: Path,
) -> str:
    ca = str(ca_cert).replace("\\", "/")
    cc = str(client_cert).replace("\\", "/")
    pk = str(private_key).replace("\\", "/")
    return f"""ctrl_interface={_WPA_CTRL}
ap_scan=0
eapol_version=1
update_config=0

network={{
    key_mgmt=IEEE8021X
    eap=TLS
    identity="{identity}"
    ca_cert={ca}
    client_cert={cc}
    private_key={pk}
}}
"""


def render_systemd_network(
    *,
    interface: str,
    dhcp_client_identifier: str | None,
    link_mac_address: str | None = None,
    vendor_class: str | None = None,
    modem_dhcp_extras: bool = False,
    dhcp_request_options: str | None = _MODEM_DHCP_REQUEST_OPTIONS,
    dhcp_max_message_size: int = _DEFAULT_DHCP_MAX_MESSAGE_SIZE,
) -> str:
    lines = [
        "[Match]",
        f"Name={interface}",
        "",
        "[Network]",
        "DHCP=ipv4",
        "RequiredForOnline=yes",
        "",
        "[Link]",
        "RequiredForOnline=yes",
    ]
    if link_mac_address:
        lines.append(f"MACAddress={link_mac_address}")
    lines.append("")

    dhcp_lines: list[str] = []
    if dhcp_client_identifier:
        dhcp_lines.append(f"ClientIdentifier={dhcp_client_identifier}")
    if modem_dhcp_extras:
        if vendor_class:
            dhcp_lines.append(f"VendorClassIdentifier={vendor_class}")
        if dhcp_request_options:
            dhcp_lines.append(f"RequestOptions={dhcp_request_options}")
        if dhcp_max_message_size:
            dhcp_lines.append(f"SendOption=57:uint16:{dhcp_max_message_size}")
    if dhcp_lines:
        lines.extend(["[DHCPv4]", *dhcp_lines, ""])
    return "\n".join(lines)


def render_wpa_supplicant_dropin(
    *,
    interface: str,
    config_path: Path,
) -> str:
    conf = str(config_path).replace("\\", "/")
    return f"""[Service]
ExecStart=
ExecStart=/usr/sbin/wpa_supplicant -c {conf} -i {interface} -D wired -t
"""


def render_readme_fragment(
    *,
    interface: str,
    pki_dir: Path,
    dhcp_client_identifier: str | None,
    eap_identity: str | None,
    wan_mac: str | None = None,
    vendor_class: str | None = None,
    product_class: str | None = None,
) -> str:
    dhcp_note = (
        f"`{dhcp_client_identifier}` (DHCP option 61 type 0 string — matches modem CMDB "
        f"``dhcpc clientid``)"
        if dhcp_client_identifier
        else "(not set — provide factory serial)"
    )
    return f"""# Lightspeed WAN 802.1X — install notes (generated)

## Legal

These files contain **per-device WAN credentials** cloned from gateway flash. Use only on
hardware you own or are authorized to test. ISP terms may prohibit impersonating the CPE.

## Generated files

| File | Install path | Purpose |
|------|--------------|---------|
| `pki/cacerts.pem` | `{pki_dir}/cacerts.pem` | ISP/operator EAP-TLS CA bundle |
| `pki/client.pem` | `{pki_dir}/client.pem` | Device client certificate |
| `pki/client.key` | `{pki_dir}/client.key` | Device private key; keep mode `0600` |
| `pki/lightspeed.p12` | Do not need to install | Raw encrypted PKCS#12 kept for recovery/reference |
| `wpa_supplicant-{interface}.conf` | `/etc/wpa_supplicant/wpa_supplicant-{interface}.conf` | Wired EAP-TLS supplicant config |
| `wpa_supplicant@{interface}.service.d/override.conf` | `/etc/systemd/system/wpa_supplicant@{interface}.service.d/override.conf` | Forces `wpa_supplicant` into wired mode for `{interface}` |
| `{interface}.network` | `/etc/systemd/network/{interface}.network` | systemd-networkd DHCP profile and modem-like DHCP options |

## Install on a systemd-networkd router

Run these from the generated directory:

```bash
sudo install -d -m 0755 {pki_dir} /etc/wpa_supplicant /etc/systemd/network /etc/systemd/system/wpa_supplicant@{interface}.service.d
sudo install -m 0644 pki/cacerts.pem {pki_dir}/cacerts.pem
sudo install -m 0644 pki/client.pem {pki_dir}/client.pem
sudo install -m 0600 pki/client.key {pki_dir}/client.key
sudo install -m 0644 wpa_supplicant-{interface}.conf /etc/wpa_supplicant/wpa_supplicant-{interface}.conf
sudo install -m 0644 wpa_supplicant@{interface}.service.d/override.conf /etc/systemd/system/wpa_supplicant@{interface}.service.d/override.conf
sudo install -m 0644 {interface}.network /etc/systemd/network/{interface}.network
```

Make sure no other network manager owns `{interface}`. On NetworkManager hosts, mark the
interface unmanaged or use a networkd-only WAN profile. On netplan hosts, set the WAN
renderer to `networkd`. Stop any standalone `dhclient`, `dhcpcd`, or distribution DHCP
client attached to `{interface}`.

Enable the services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wpa_supplicant@{interface}.service
sudo systemctl enable --now systemd-networkd.service
sudo networkctl reload
sudo networkctl reconfigure {interface}
```

If the link was already up with the wrong MAC, bring it down before reconfiguring:

```bash
sudo ip link set {interface} down
sudo networkctl reconfigure {interface}
sudo ip link set {interface} up
```

**Order:** wpa_supplicant must complete **EAP-TLS** before DHCP is useful. The `.network` unit
should start after `wpa_supplicant@{interface}.service`; if DHCP races ahead of EAP, restart
`systemd-networkd` after the supplicant reports `CTRL-EVENT-EAP-SUCCESS`.

## Parameter mapping (modem → Linux)

| Modem (`lmd`) | This bundle |
|---------------|-------------|
| `eap pkcs12` + `lightspeed_p12` (NAND `tlpart`) | `lightspeed.p12` + `client.pem` / `client.key` |
| `/etc/pki/eapol/cacerts.pem` | `cacerts.pem` (from `att_unified_eapol-certs.pkgstream`) |
| EAP identity (default MAC CN) | wpa `identity="{eap_identity or "?"}"` |
| `dhcpc clientid` | networkd `ClientIdentifier` = {dhcp_note} |
| Factory `mac=` / cert CN | `[Link] MACAddress` = {wan_mac or "(not set)"} (DHCP **chaddr**) |
| Vendor class (opt 60) | `{vendor_class or "(optional — pass --vendor-class)"}` |
| Parameter request list (opt 55) | Emitted when `--modem-dhcp` (systemd **RequestOptions**) |
| Max message size (opt 57) | `1500` via **SendOption** when `--modem-dhcp` |
| V-I opts 124 / 125 (2Wire / BBF) | Not in `.network` — see **DHCP options not in systemd** below |

## WPA supplicant notes

`wpa_supplicant-{interface}.conf` uses wired EAP-TLS:

- `ap_scan=0` because this is Ethernet, not Wi-Fi scanning.
- `key_mgmt=IEEE8021X` and `eap=TLS` match the gateway's WAN EAPOL behavior.
- `identity="{eap_identity or "?"}"` is normally the certificate CN, often the WAN MAC.
- `ca_cert`, `client_cert`, and `private_key` point at `{pki_dir}` after installation.

Use `journalctl -u wpa_supplicant@{interface}.service -f` while testing. The success marker is
`CTRL-EVENT-EAP-SUCCESS`; DHCP will not work reliably before that.

## systemd-networkd and DHCP notes

`{interface}.network` sets `DHCP=ipv4` and, when available, clones the modem WAN MAC with
`[Link] MACAddress={wan_mac or "(not set)"}`. This controls DHCP **chaddr** and is separate
from the EAP identity and option 61 client identifier.

The generated DHCP section sends `ClientIdentifier={dhcp_client_identifier or "(not set)"}`.
With modem parity enabled, it also sends option 60 (`VendorClassIdentifier`), option 55
(`RequestOptions`), and option 57 (`SendOption=57:uint16:1500`).

## DHCP options not in systemd-networkd

Modem **REQUEST** packets also carry **option 124** (enterprise {_TWOWIRE_DHCP_ENTERPRISE} / 2Wire, often empty) and **option 125**
(Broadband Forum enterprise {_BBF_DHCP_ENTERPRISE}: DeviceManufacturerOUI=`{CONNREQ_OUI}`, DeviceSerialNumber, DeviceProductClass=`{product_class or "homeportal"}`).
systemd-networkd has no first-class encoder for those TLV blobs; use **dhclient**/**dhcpcd** hooks or verify the BNG only enforces opt **61** + **chaddr**.

**Renewal-only** (omit on DISCOVER): option **50** (requested IP), **54** (server id).

## Verify

- `systemctl status wpa_supplicant@{interface}.service systemd-networkd.service`
- `networkctl status {interface}`
- `journalctl -u wpa_supplicant@{interface}.service -u systemd-networkd.service -b`
- Compare DHCP DISCOVER **option 61** to modem capture (type `0x00` + ASCII client-id string).
- **chaddr** must match the modem WAN MAC (`MACAddress` above); client-id string is separate.
- Capture with `tcpdump -ni {interface} -vvv ether proto 0x888e or port 67 or port 68`.
"""


def gen_network_config(
    *,
    interface: str = "wan0",
    profile: Profile = "router",
    out_dir: Path,
    pki_dir: Path | None = None,
    ca_cert: Path | None = None,
    eapol_certs_pkgstream: Path | None = None,
    client_pem: Path | None = None,
    eap_identity: str | None = None,
    wan_mac: str | None = None,
    clone_wan_mac: bool = True,
    dhcp_client_id_override: str | None = None,
    serial: str | None = None,
    subject: str | None = None,
    flash_path: str | Path | None = None,
    cert: CertKind = "lightspeed",
    include_p12: bool = True,
    vendor_class: str | None = None,
    firmware_version: str | None = None,
    product_class: str = "homeportal",
    modem_dhcp_match: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
  Write wpa_supplicant + systemd-networkd snippets under ``out_dir``.

  With ``flash_path``, runs ``dump_eapol_cert`` (``lightspeed_p12`` from NAND ``tlpart``) and
  writes ``pki/lightspeed.p12`` plus split ``client.pem`` / ``client.key``. CA resolves from
  ``ca_cert``, pre-extracted prod PEM, or ``eapol_certs_pkgstream`` (default unified pkgstream).
  """
    if profile != "router":
        raise ValueError(f"unsupported profile: {profile!r}")

    out = Path(out_dir).expanduser().resolve()
    pki_install = (pki_dir or _DEFAULT_PKI_DIR).expanduser()
    pki_out = out / "pki"
    p12_out = pki_out / f"{cert}.p12"
    pem_out = pki_out / f"{cert}_eapol.pem"
    doc: dict[str, Any] = {
        "ok": False,
        "profile": profile,
        "interface": interface,
        "out_dir": str(out),
        "pki_dir": str(pki_install),
        "pki_out": str(pki_out),
    }

    pem_bytes: bytes | None = None
    p12_path: Path | None = None
    if flash_path is not None:
        from paceflash.eapol_cert import dump_eapol_cert

        eap_doc = dump_eapol_cert(
            flash_path,
            cert=cert,
            decrypt=True,
            output_pem=pem_out,
            output_p12=p12_out if include_p12 else None,
            include_pem=dry_run,
            write_files=not dry_run,
        )
        doc["eapol"] = {k: v for k, v in eap_doc.items() if k != "pem"}
        if not eap_doc.get("ok"):
            doc["error"] = eap_doc.get("error", "dump-eapol-cert failed")
            return doc
        if dry_run:
            pem_raw = eap_doc.get("pem")
            if pem_raw is None:
                doc["error"] = "dump-eapol-cert did not produce PEM"
                return doc
            pem_bytes = (
                pem_raw
                if isinstance(pem_raw, bytes)
                else pem_raw.encode() if isinstance(pem_raw, str) else bytes(pem_raw)
            )
        else:
            pem_path = eap_doc.get("pem_path")
            if not pem_path:
                doc["error"] = "dump-eapol-cert did not produce PEM"
                return doc
            pem_bytes = Path(pem_path).read_bytes()
            p12_written = eap_doc.get("p12_path")
            if include_p12 and p12_written:
                p12_path = Path(p12_written)
        serial = serial or eap_doc.get("serial")
        subject = subject or eap_doc.get("subject")
    elif client_pem is not None:
        pem_bytes = Path(client_pem).expanduser().read_bytes()
    else:
        doc["error"] = "flash_path or client_pem required"
        return doc

    try:
        ca_path = resolve_ca_cert(ca_cert, eapol_certs_pkgstream=eapol_certs_pkgstream)
    except FileNotFoundError as exc:
        doc["error"] = str(exc)
        return doc
    doc["ca_cert"] = str(ca_path)

    dhcp_id = dhcp_client_id_override or dhcp_client_id(
        serial if isinstance(serial, str) else None
    )
    identity = eap_identity or eap_identity_from_subject(
        subject if isinstance(subject, str) else None
    )
    if not identity:
        doc["error"] = "could not determine EAP identity (pass --identity or use flash dump)"
        return doc

    link_mac: str | None = None
    if clone_wan_mac:
        link_mac = resolve_wan_mac(
            wan_mac,
            identity=identity,
            flash_path=flash_path,
        )
    doc["wan_mac"] = link_mac

    vclass = (vendor_class or "").strip() or vendor_class_identifier(firmware_version)
    doc["vendor_class"] = vclass
    doc["product_class"] = product_class

    cert_pem, key_pem = split_pem_bundle(pem_bytes)

    files = {
        "wpa_supplicant.conf": out / f"wpa_supplicant-{interface}.conf",
        "wpa_supplicant.dropin": out / f"wpa_supplicant@{interface}.service.d" / "override.conf",
        "systemd.network": out / f"{interface}.network",
        "README.md": out / "README.md",
    }
    pki_files = {
        "cacerts.pem": pki_install / "cacerts.pem",
        "client.pem": pki_install / "client.pem",
        "client.key": pki_install / "client.key",
    }
    pki_out_files: dict[str, Path] = {
        "cacerts.pem": pki_out / "cacerts.pem",
        "client.pem": pki_out / "client.pem",
        "client.key": pki_out / "client.key",
    }
    if include_p12 and flash_path is not None:
        pki_out_files[f"{cert}.p12"] = p12_out
    if flash_path is not None:
        pki_out_files[f"{cert}_eapol.pem"] = pem_out
    doc["files"] = {k: str(v) for k, v in files.items()}
    doc["pki_files"] = {k: str(v) for k, v in pki_files.items()}
    doc["pki_out_files"] = {k: str(v) for k, v in pki_out_files.items()}
    if p12_path is not None:
        doc["lightspeed_p12"] = str(p12_path)
    doc["dhcp_client_identifier"] = dhcp_id
    doc["eap_identity"] = identity

    wpa_text = render_wpa_supplicant_conf(
        interface=interface,
        identity=identity,
        ca_cert=pki_files["cacerts.pem"],
        client_cert=pki_files["client.pem"],
        private_key=pki_files["client.key"],
    )
    net_text = render_systemd_network(
        interface=interface,
        dhcp_client_identifier=dhcp_id,
        link_mac_address=link_mac,
        vendor_class=vclass,
        modem_dhcp_extras=modem_dhcp_match,
    )
    dropin_text = render_wpa_supplicant_dropin(
        interface=interface,
        config_path=Path(f"/etc/wpa_supplicant/wpa_supplicant-{interface}.conf"),
    )
    readme_text = render_readme_fragment(
        interface=interface,
        pki_dir=pki_install,
        dhcp_client_identifier=dhcp_id,
        eap_identity=identity,
        wan_mac=link_mac,
        vendor_class=vclass,
        product_class=product_class,
    )

    if dry_run:
        doc["ok"] = True
        doc["dry_run"] = True
        return doc

    if not out.exists():
        out.mkdir(parents=True, exist_ok=True)
    files["wpa_supplicant.dropin"].parent.mkdir(parents=True, exist_ok=True)
    pki_out.mkdir(parents=True, exist_ok=True)

    ca_bytes = ca_path.read_bytes()
    pki_out_files["cacerts.pem"].write_bytes(ca_bytes)
    pki_out_files["client.pem"].write_bytes(cert_pem)
    pki_out_files["client.key"].write_bytes(key_pem)
    # PEM/P12 from dump_eapol_cert already written when flash_path set; refresh bundle PEM
    if flash_path is not None and pem_out in pki_out_files:
        pem_out.write_bytes(pem_bytes)

    files["wpa_supplicant.conf"].write_text(wpa_text, encoding="utf-8", newline="\n")
    files["wpa_supplicant.dropin"].write_text(dropin_text, encoding="utf-8", newline="\n")
    files["systemd.network"].write_text(net_text, encoding="utf-8", newline="\n")
    files["README.md"].write_text(readme_text, encoding="utf-8", newline="\n")

    doc["ok"] = True
    return doc
