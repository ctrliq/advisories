# CIQ Security Advisories

Security advisories published by CIQ in [OASIS CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html) format.

## Repository Structure

```
.
├── csaf/
│   ├── advisories/
│   │   ├── rocky/            # Rocky Linux from CIQ advisories (CRLSA/CRLBA/CRLEA)
│   │   │   └── {year}/
│   │   └── ciq/              # CIQ product advisories (CIQSA)
│   │       └── {year}/
│   └── vex/                  # Vulnerability Exploitability Exchange (VEX) data
│       └── cve/
│           └── {year}/
├── mapping/
│   └── cpe-repo-map.json     # Host CPE to repo CPE mapping
└── README.md
```

## Security Advisories

This repository contains advisories that have associated CVEs. Bug fix
and enhancement advisories without CVE references are not included.

### Rocky Linux from CIQ (`csaf/advisories/rocky/`)

CSAF 2.0 transformations of [Rocky Linux security advisories](https://errata.rockylinux.org/)
published by the Rocky Enterprise Software Foundation (RESF). These cover
Rocky Linux packages distributed by CIQ across all supported product tiers
(Plus, Pro, Pro Hardened).

| Prefix | Type | Description |
|--------|------|-------------|
| CRLSA | Security | Security vulnerability fixes |
| CRLBA | Bug Fix | Bug fix updates (CVE-associated only) |
| CRLEA | Enhancement | Feature enhancements (CVE-associated only) |

**Path:** `csaf/advisories/rocky/{year}/{tracking-id}.json`

**Example:** `csaf/advisories/rocky/2023/crlsa-2023_0005.json`

### CIQ Product Advisories (`csaf/advisories/ciq/`)

Security advisories for CIQ-specific repositories that extend beyond
upstream Rocky Linux, including Long Term Support (LTS) releases, FIPS
certified/compliant builds, and CentOS Linux Bridge.

**Advisory ID format:** `CIQSA-{year}:{sequence}` (e.g., `CIQSA-2026:0001`)

**Path:** `csaf/advisories/ciq/{year}/{tracking-id}.json`

**Example:** `csaf/advisories/ciq/2026/ciqsa-2026_0001.json`

**Covered repositories:**
- LTS (9.6)
- FIPS Certified (8.6, 8.10, 9.2, 9.6)
- FIPS Compliant (8.6, 8.10, 9.2, 9.6)
- CentOS Linux Bridge (7.9)

## VEX Data

[Vulnerability Exploitability eXchange (VEX)](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
documents provide per-CVE fix status for CIQ repositories. Each document
addresses a single CVE and follows the
[CSAF VEX profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#45-profile-5-vex).

**Path:** `csaf/vex/cve/{year}/{cve-id}.json`

**Example:** `csaf/vex/cve/2024/cve-2024-1234.json`

### Product ID Format

CSAF `product_id` fields use the format:
```
{repo-key}:{package-name}-{version}-{release}.{distro}.{arch}
```

**Example:** `lts-9.6:openssl-3.0.7-28.el9_4.92ciq.x86_64`

## CPE Repo Map (`mapping/cpe-repo-map.json`)

Maps host system CPEs (as found in `/etc/system-release-cpe`) to the
repo-level CPEs used in advisory `product_tree` nodes. Vulnerability
scanners use this to correlate a host's identity with applicable
advisories.

**Schema:**
```json
{
  "version": "1.0",
  "generated_at": "2026-09-01T...",
  "mappings": {
    "<host-cpe>": ["<repo-cpe>", "..."]
  }
}
```

**Keys** are the truncated CPE 2.3 string from the host's
`/etc/system-release-cpe` (e.g., `cpe:2.3:o:ciq:rocky_linux_from_ciq_pro:9.8`).

**Values** are repo-level CPEs that appear in advisory `product_tree`
nodes (e.g., `cpe:2.3:o:ciq:rocky_linux_from_ciq:9:*:*:*:*:*:*:appstream`).

### Scanner Integration

1. Read the host's CPE from `/etc/system-release-cpe`
2. Look up the host CPE in `mapping/cpe-repo-map.json`
3. The returned repo CPEs identify which advisory `product_tree` entries
   apply to this host
4. Match repo CPEs against advisory documents to find applicable fixes

```bash
# Find repo CPEs for a host
HOST_CPE=$(cat /etc/system-release-cpe)
jq --arg cpe "$HOST_CPE" '.mappings[$cpe]' mapping/cpe-repo-map.json
```

## Usage Examples

### Find advisories for a specific CVE

```bash
# Check VEX status
jq '.vulnerabilities[0].product_status' csaf/vex/cve/2024/cve-2024-1234.json

# Search Rocky Linux advisories
grep -rl "CVE-2024-1234" csaf/advisories/rocky/
```

### List advisories for a repository

```bash
# Find all advisories mentioning the LTS 9.6 repo
grep -rl "lts-9.6" csaf/advisories/ciq/
```

### Get applicable advisories for a host

```bash
# 1. Get the host CPE
HOST_CPE="cpe:2.3:o:ciq:rocky_linux_from_ciq_pro:9.8"

# 2. Look up repo CPEs
REPO_CPES=$(jq -r --arg cpe "$HOST_CPE" '.mappings[$cpe][]' mapping/cpe-repo-map.json)

# 3. Search advisories for matching CPEs
for cpe in $REPO_CPES; do
  grep -rl "$cpe" csaf/advisories/
done
```

## CSAF 2.0 Compliance

All documents conform to CSAF 2.0:

- **Advisories** follow the [Security Advisory profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#44-profile-4-security-advisory)
- **VEX documents** follow the [VEX profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#45-profile-5-vex)
- Year-based folders per [Section 7.1.11](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7111-requirement-11-one-folder-per-year)

## Related Resources

- [CSAF 2.0 Specification](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
- [Rocky Linux Errata](https://errata.rockylinux.org/)
- [CISA VEX Documentation](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
