# CIQ Security Advisories
This repository contains security advisories published by CIQ. The primary format used for security advisories is the [OASIS Common Security Advisory Framework (CSAF) Version 2.0 standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html).

## Repository Structure

### VEX Data
[Vulnerablity Exploitabilty eXchange (VEX)](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex) are stored under the `csaf/vex/` folder with a path like:

```
csaf/vex/cve/{cve year}/{cve id}.json
```

VEX json documents meet the requirements of the [CSAF VEX document profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#45-profile-5-vex) with the additional restriction that they only address a single CVE per document.

CSAF `product_id` fields for CIQ products should be in the format:
```
{ciq product key}:{package name}-{package version}-{release}.{distro}.{arch}
```

### Security Advisories
Security advisories are stored under the `csaf/advisories/` folder with a path like:

```
csaf/advisories/{publisher}/{year}/{advisory-id}.json
```

Security advisory CSAF documents meet the requirements of the [CSAF Security Advisory profile](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#41-profile-1-csaf-base) with document category `csaf_security_advisory`. These advisories aggregate security fixes for specific packages or SRPMs and may address one or more CVEs.

Advisory naming conventions:
- CIQ advisories: `ciqsa-{product}-{version}-{year}-{sequence}.json` (e.g., `ciqsa-cbr-7-9-2026-0001.json`)
- Rocky Linux advisories follow similar patterns organized by publisher and year