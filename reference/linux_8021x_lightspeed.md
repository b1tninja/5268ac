# Linux router 802.1X — Lightspeed / 5268AC mapping

Firmware: **`att-5268-11.5.1.532678_prod_lightspeed-install`**. Ghidra target: **`/usr/bin/lmd`**. Offline credentials: **`paceflash dump-eapol-cert`**, **`paceflash factory-params`**. Config generator: **`paceflash gen-network-config`**.

Related: [`eapol_8021x_p12.md`](eapol_8021x_p12.md), [`paceflash.md`](paceflash.md), [`board_params_nand.md`](board_params_nand.md).

---

## Stack (router profile)

```mermaid
flowchart LR
  subgraph host [Linux router]
    WPA[wpa_supplicant@wan0]
    NET[systemd-networkd]
    NIC[wan0]
  end
  ISP[ISP access network]

  NIC --> WPA
  WPA -->|EAP-TLS 0x888e| ISP
  WPA -->|authenticated| NET
  NET -->|DHCP opt61| ISP
```

1. **wpa_supplicant** — wired supplicant (`-D wired`, `ap_scan=0`, `eap=TLS`).
2. **systemd-networkd** — DHCP on the same interface **after** 802.1X succeeds.

The modem runs EAPOL inside **`lmd`** on a logical **`eapol0`** module bound to **`pm_bb_bridge`** (`dsl0` + `eth4`). On Linux you use one physical WAN NIC; no bridge is required unless you deliberately mirror the modem topology.

---

## Parameter translation

| Modem (`lmd` / CMDB) | Linux |
|----------------------|--------|
| `eap pkcs12` = `lightspeed` | Decrypt `lightspeed_p12` → `client.pem` + `client.key` |
| `lightspeed_p12` (board_param) | `paceflash dump-eapol-cert` |
| `/etc/pki/eapol/cacerts.pem` | `ca_cert=` → install operator bundle from `att_unified_eapol-certs.pkgstream` |
| EAP identity (default WAN **MAC** CN) | wpa_supplicant `identity="14:ED:BB:DF:ED:5C"` |
| Factory `mac=` / cert CN | `wan0.network` `[Link] MACAddress=14:ED:BB:DF:ED:5C` (DHCP **chaddr**) |
| **`dhcpc clientid`** = `00D09E-{sn}` | `[DHCPv4] ClientIdentifier=00D09E-{sn}` |
| **chaddr** | Interface MAC (independent of option 61) |
| `eapol_version` = 1 | `eapol_version=1` |
| Vendor class (opt **60**) | `[DHCPv4] VendorClassIdentifier=2WHPL M.m.b` from `board_build_digits` |
| Parameter list (opt **55**) | `[DHCPv4] RequestOptions=…` (modem’s 19-option list) |
| Max message size (opt **57**) | `SendOption=57:uint16:1500` |
| V-I vendor class (opt **124**) | Enterprise **4839** (2Wire/Pace), often **empty** — not in systemd-networkd |
| V-I vendor info (opt **125**) | Enterprise **3561** (BBF): OUI, serial, product class — needs dhclient/hook |
| Requested IP / server id (opt **50** / **54**) | **Renewal only** — systemd adds these on renew |

**Important:** EAP **identity** (often certificate **CN** = colon-MAC) is **not** the same string as the **DHCP client identifier** (`00D09E-38161N043704`).

---

## Generate configs

### Prerequisites

```powershell
pip install -e ".[eapol]"
```

Extract operator CA (once per carrier tree):

```powershell
python -m lib2spy firmware_11.5.1.532678/.../att_unified_eapol-certs.pkgstream --extract ./tmp-eapol-ca
# Use tmp-eapol-ca/.../lightspeed-prod-cacerts.pem as --ca-cert
```

### From flash dump

```powershell
# lightspeed_p12 + CA + DHCP modem parity (opt 61, MAC, 2WHPL, param list, max-msg 1500)
python -m paceflash gen-network-config "PACE 5268AC S34ML01G1@TSOP48.BIN" `
  --out-dir .\lightspeed-network `
  --interface wan0 `
  --firmware-version "11.5.1.532678"

# Align with a WAN capture (MAC / version line may differ from factory mac= / cert CN)
python -m paceflash gen-network-config "PACE ….BIN" `
  --wan-mac d4:b2:7a:6b:b1:4c `
  --firmware-version "11.14.1.123456" `
  --out-dir .\lightspeed-network
```

`python -m paceflash gen-network-config --help` lists all flags (`--no-modem-dhcp`, `--vendor-class`, …).

### From existing PEM

```powershell
python -m paceflash gen-network-config `
  --client-pem output\lightspeed_eapol.pem `
  --serial 38161N043704 `
  --firmware-version "11.5.1.532678" `
  --out-dir .\lightspeed-network
```

### Output layout

| Path | Role |
|------|------|
| `wpa_supplicant-wan0.conf` | wpa_supplicant network block |
| `wpa_supplicant@wan0.service.d/override.conf` | systemd unit drop-in |
| `wan0.network` | systemd-networkd match + DHCP |
| `pki/` | `lightspeed.p12`, `lightspeed_eapol.pem`, `cacerts.pem`, `client.pem`, `client.key` (install split PEM + CA to `/etc/pki/eapol/`) |
| `README.md` | Install + legal notes |

---

## Example `wan0.network`

```ini
[Match]
Name=wan0

[Network]
DHCP=ipv4
RequiredForOnline=yes

[Link]
RequiredForOnline=yes
MACAddress=14:ED:BB:DF:ED:5C

[DHCPv4]
ClientIdentifier=00D09E-38161N043704
VendorClassIdentifier=2WHPL 11.5.1
RequestOptions=1 2 3 6 15 42 44 46 47 23 24 25 26 35 36 119 121 249 212
SendOption=57:uint16:1500
```

- **`ClientIdentifier`**: option **61** (type `0x00` + ASCII `00D09E-{factory_serial}`).
- **`MACAddress`**: DHCP **chaddr** (clone modem WAN MAC if it differs from cert CN).
- **`VendorClassIdentifier` / `RequestOptions` / `SendOption`**: omitted when **`--no-modem-dhcp`**.

---

## Example `wpa_supplicant-wan0.conf`

```
ctrl_interface=/run/wpa_supplicant
ap_scan=0
eapol_version=1

network={
    key_mgmt=IEEE8021X
    eap=TLS
    identity="14:ED:BB:DF:ED:5C"
    ca_cert=/etc/pki/eapol/cacerts.pem
    client_cert=/etc/pki/eapol/client.pem
    private_key=/etc/pki/eapol/client.key
}
```

---

## Install order

1. Copy `pki/*` → `/etc/pki/eapol/`; `chmod 600 /etc/pki/eapol/client.key`
2. Install wpa_supplicant config under `/etc/wpa_supplicant/`
3. Install unit drop-in for `wpa_supplicant@wan0.service`
4. Install `.network` under `/etc/systemd/network/`
5. `systemctl daemon-reload`
6. `systemctl enable --now wpa_supplicant@wan0`
7. `systemctl restart systemd-networkd`

Add `After=wpa_supplicant@wan0.service` to the `.network` unit drop-in if DHCP races ahead of EAP completion.

---

## DHCP REQUEST field guide (modem capture)

Typical **`lmd`** WAN **REQUEST** after 802.1X (your capture is a **renew** — options **50** / **54** present):

| Field | Modem | Linux (`gen-network-config`) |
|-------|--------|------------------------------|
| **chaddr** | WAN MAC (e.g. `d4:b2:7a:6b:b1:4c`) | `[Link] MACAddress=` (clone modem/factory MAC) |
| **Option 61** | Type `0x00` + ASCII `00D09E-{sn}` | `ClientIdentifier=00D09E-{sn}` |
| **Option 60** | `2WHPL 11.14.1` (first three version digits) | `VendorClassIdentifier=` (`--firmware-version` or `--vendor-class`) |
| **Option 57** | `1500` | `SendOption=57:uint16:1500` |
| **Option 55** | 19 parameters (mask, router, DNS, …) | `RequestOptions=1 2 3 6 …` |
| **Option 124** | Enterprise 4839, length 0 | Not generated — rarely required |
| **Option 125** | BBF 3561: OUI `00D09E`, serial, `homeportal` | Documented in README; use custom DHCP client if BNG requires it |
| **Option 50/54** | Renew only | systemd-networkd on renew |

**Note:** Factory **`mac=`** (Pace `14:ED:BB:…`) can differ from **chaddr** on some builds (e.g. Commscope OUI on WAN) — clone the **MAC you see in captures**, not only the cert CN.

```powershell
python -m paceflash gen-network-config "PACE ….BIN" `
  --firmware-version "11.14.1.123456" `
  --vendor-class "2WHPL 11.14.1"
```

## Verify against packet capture

| Field | Expect |
|-------|--------|
| EAPOL | EAP-TLS; identity often MAC from cert CN |
| DHCP option 61 | Type `0x00`, payload ASCII `00D09E-{sn}` |
| DHCP chaddr | WAN interface MAC |
| DHCP vendor class | `2WHPL M.m.b` when `--modem-dhcp` (default) |
| DHCP option 55/57 | Match modem if parity matters to your BNG |

---

## Legal

Generated material is **device identity**. Use only on hardware you control. See [`LEGAL.md`](../LEGAL.md).
