# Gateway firmware CDN — S3 bucket and listing

## Bucket identity

| Field | Value |
|--------|--------|
| **S3 bucket** | `ecouverseprodeast-firmware` |
| **AWS account** | `601471275036` |
| **Public hostname** | `gateway.c01.sbcglobal.net` |
| **DNS** | CNAME → `…att-idns.net` → **`d3s4wzxismc942.cloudfront.net`** |
| **Object key prefix** | `firmware/{device_code}/…` (same path as HTTPS URL after host) |

Example object key (5268):

```text
firmware/00D09E/11.5.1.532678-PROD/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream
```

HTTPS URL (what devices and `wget` use):

```text
https://gateway.c01.sbcglobal.net/firmware/00D09E/11.5.1.532678-PROD/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream
```

## What broke vs what still works

| Operation | Anonymous | IAM `vcdn` (your error) |
|-----------|-----------|-------------------------|
| **`s3:ListBucket`** on `ecouverseprodeast-firmware` | **AccessDenied** | **AccessDenied** (no identity policy for ListBucket) |
| **`s3:GetObject`** via **S3 API** (`aws s3api head-object` / direct `s3://`) | **403 Forbidden** (tested 2026-05-22) | Likely allowed if policy grants `GetObject` only |
| **HTTP GET via CloudFront** (`gateway.c01.sbcglobal.net/…`) | **200** on known keys (`server: AmazonS3`, `via: CloudFront`) | N/A (use HTTPS URL) |

So: **listing was disabled at the bucket policy / IAM layer**, not “the bucket vanished.” **Public read of known objects** is still exposed through **CloudFront**, not through anonymous `aws s3 ls` or `s3://` URLs.

Your log line:

```text
User: arn:aws:iam::601471275036:user/vcdn is not authorized to perform: s3:ListBucket
on resource: "arn:aws:s3:::ecouverseprodeast-firmware"
because no identity-based policy allows the s3:ListBucket action
```

means the **`vcdn`** user is intentionally (or effectively) **read-object-only** — same class of restriction as anonymous listing, but **authenticated** for CDN/origin workflows.

## WSL / AWS CLI checks

**Listing (expect failure):**

```bash
aws s3 ls s3://ecouverseprodeast-firmware/firmware/00D09E/ \
  --region us-east-1

# or anonymous
aws s3 ls s3://ecouverseprodeast-firmware/firmware/00D09E/ \
  --no-sign-request --region us-east-1
```

**S3 XML listing on the CloudFront hostname (also denied):**

```bash
curl -sS "https://gateway.c01.sbcglobal.net/?list-type=2&prefix=firmware/00D09E/&max-keys=3"
# → <Code>AccessDenied</Code>
```

**Download a known object (works without AWS creds):**

```bash
curl -fLO "https://gateway.c01.sbcglobal.net/firmware/00D09E/11.5.1.532678-PROD/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream"
```

Use **`--profile`** (or env keys) for **`vcdn`** only if you need **S3 API** `GetObject`/`HeadObject` against the **origin** bucket; for research, **HTTPS via `gateway.c01…` is the path that matches the device**.

## Rebuilding `pkgstreams` without ListBucket

1. **Keep** the historical [`pkgstreams`](../pkgstreams) snapshot (from when listing worked).
2. **Discover new builds** by version hint + **HEAD/GET** on predictable URLs (see [`acspy.md`](acspy.md)), not `aws s3 ls`.
3. **Optional:** if `vcdn` can **`s3:GetObject`** but not list, you still need **exact keys** (from CMDB, upgrade `redirect_url`, or naming pattern) — same as CloudFront GET.

## Related

- [`firmware.md`](firmware.md) — CDN path layout
- [`acspy.md`](acspy.md) — offline catalog + URL construction
- Probe scripts: [`tools/probe_gateway_s3.sh`](../tools/probe_gateway_s3.sh) (HTTP), install `aws-cli-v2` on Arch WSL for `aws s3` tests
