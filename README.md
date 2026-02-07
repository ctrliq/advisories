# CIQ Security Advisories

This repository contains security advisories published by CIQ. All advisory documents follow the [OASIS Common Security Advisory Framework (CSAF) Version 2.0 standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html).

## Repository Structure

```
.
├── csaf/
│   ├── advisories/           # CSAF 2.0 Security Advisories
│   │   ├── rocky/            # Rocky Linux from CIQ advisories (CRLSA/CRLBA/CRLEA)
│   │   │   └── {year}/       # Organized by publication year
│   │   └── ciq/              # CIQ product advisories (CIQSA)
│   │       └── {year}/       # Organized by publication year
│   └── vex/                  # Vulnerability Exploitability Exchange data
│       └── cve/
│           └── {year}/       # Organized by CVE year
├── mapping/                  # Machine-readable mapping files
│   └── cpe-product-keys.json # CPE to product key mapping
└── README.md
```

## Security Advisories

**Note:** This repository contains only advisories that have associated CVEs. Bug fix and enhancement advisories without CVE references are not included.

### Rocky Linux from CIQ Advisories (`csaf/advisories/rocky/`)

These advisories are CSAF 2.0 transformations of [Rocky Linux security advisories](https://errata.rockylinux.org/) published by the Rocky Enterprise Software Foundation (RESF). They provide security information for Rocky Linux packages distributed by CIQ.

**Advisory Types:**
| Prefix | Type | Description |
|--------|------|-------------|
| CRLSA | Security | Security vulnerability fixes |
| CRLBA | Bug Fix | Bug fix updates (only if CVE-associated) |
| CRLEA | Enhancement | Feature enhancements (only if CVE-associated) |

**Path format:**
```
csaf/advisories/rocky/{year}/{tracking-id}.json
```

**Example:** `csaf/advisories/rocky/2025/crlsa-2025-20841.json`

### CIQ Product Advisories (`csaf/advisories/ciq/`)

These are security advisories for CIQ-specific products that extend beyond standard Rocky Linux, including Long Term Support (LTS) releases, FIPS certified/compliant builds, and CentOS Linux Bridge.

**Advisory ID Format:** `CIQSA-{product-key}-{year}:{sequence}`

**Path format:**
```
csaf/advisories/ciq/{year}/{tracking-id}.json
```

**Example:** `csaf/advisories/ciq/2026/ciqsa-lts-9-2-2026-0001.json`

**Covered Products:**
- Rocky Linux LTS (lts-8.6, lts-8.8, lts-9.2, lts-9.4)
- Rocky Linux FIPS Certified (fips-8.6-certified, fips-8.10-certified, fips-9.2-certified)
- Rocky Linux FIPS Compliant (fips-8-compliant, fips-9.2-compliant)
- CentOS Linux Bridge (cbr-7.9)

## VEX Data

[Vulnerability Exploitability eXchange (VEX)](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex) documents are stored under `csaf/vex/` and provide per-CVE fix status information for CIQ products.

**Path format:**
```
csaf/vex/cve/{cve-year}/{cve-id}.json
```

**Example:** `csaf/vex/cve/2024/cve-2024-1234.json`

VEX documents meet the requirements of the [CSAF VEX document profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#45-profile-5-vex) with the additional restriction that each document addresses only a single CVE.

### Product ID Format

CSAF `product_id` fields for CIQ products use the format:
```
{product-key}:{package-name}-{version}-{release}.{distro}.{arch}
```

**Example:** `lts-9.2:openssl-3.0.7-18.el9_2.92ciq.x86_64`

## Mapping Files

### CPE to Product Key Mapping (`mapping/cpe-product-keys.json`)

This file provides a machine-readable mapping between [CPE 2.3](https://nvd.nist.gov/products/cpe) identifiers and CIQ product keys. This enables automated tools to filter advisories by CPE.

**Schema:**
```json
{
  "version": "1.0",
  "description": "Maps CPE 2.3 identifiers to CIQ product keys for advisory filtering",
  "generated_at": "2026-02-06T23:28:29Z",
  "mappings": {
    "cpe:2.3:o:ciq:rocky_linux_from_ciq_lts:9.2:*:*:*:*:*:*:*": "lts-9.2",
    "cpe:2.3:o:ciq:rocky_linux_fips_certified:8.10:*:*:*:*:*:*:*": "fips-8.10-certified"
  }
}
```

**Use Case:** Security scanners and vulnerability management tools can use this mapping to:
1. Identify which CIQ product key corresponds to a system's CPE
2. Filter VEX and advisory data to only relevant products
3. Automate remediation workflows based on product-specific advisories

## CSAF 2.0 Compliance

All documents in this repository conform to CSAF 2.0 specifications:

- **Advisories** (`csaf/advisories/`) follow the [CSAF Security Advisory profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#44-profile-4-security-advisory)
- **VEX documents** (`csaf/vex/`) follow the [CSAF VEX profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#45-profile-5-vex)
- Documents are organized in year-based folders per [Section 7.1.11](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7111-requirement-11-one-folder-per-year)

## Usage Examples

### Find advisories for a specific CVE

```bash
# Search Rocky Linux from CIQ advisories
grep -r "CVE-2024-1234" csaf/advisories/rocky/

# Check VEX status
cat csaf/vex/cve/2024/cve-2024-1234.json | jq '.vulnerabilities[0].product_status'
```

### List all advisories for a product

```bash
# Find all LTS 9.2 advisories
grep -l "lts-9.2" csaf/advisories/ciq/**/*.json
```

### Get CPE mapping for a product

```bash
# Find product key for a CPE
jq '.mappings["cpe:2.3:o:ciq:rocky_linux_from_ciq_lts:9.2:*:*:*:*:*:*:*"]' mapping/cpe-product-keys.json
```

## Related Resources

- [CSAF 2.0 Specification](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
- [Rocky Linux Errata](https://errata.rockylinux.org/)
- [CISA VEX Documentation](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
