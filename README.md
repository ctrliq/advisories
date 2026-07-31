# CIQ Security Advisories — Tenable preview branch

> ## ⚠️ SAMPLE DATA — NOT AUTHORITATIVE
>
> This branch is **hand-crafted sample data**, produced so Tenable can begin modelling a CIQ scanning
> plugin before CIQ's pipeline can emit the real artifacts. **Its purpose is to demonstrate document
> structure.**
>
> The data is **not guaranteed to be correct, real or accurate**, and **must not be used to assess the
> security posture of any system**. In particular, the association between a CVE and a specific build
> may be constructed rather than real. See [What is real and what is not](#what-is-real-and-what-is-not).
>
> Authoritative advisories are on the `main` branch and at
> <https://github.com/ctrliq/advisories>. Nothing here is published to customers.
>
> The same notice is repeated inside every document at `document.notes[0]`, so it travels with a file
> pulled into a test harness on its own.

Everything in this branch is new. It shares no history and no files with `main`.

---

## What is different from `main`

Three things, and only three. Everything else in each document — CVSS scoring, CWE, severity,
remediations, publisher, TLP, legal disclaimer — is produced by CIQ's existing generators, so the diff
you are reading is confined to identity and product modelling.

| # | Change | Why |
|---|---|---|
| 1 | **CIQSA identity is `CIQSA-YYYY:NNNN`** — no product slug | One advisory per *source build*, so a document can span products. `main` uses `CIQSA-<product_slug>-YYYY:NNNN` |
| 2 | **`product_tree` platform leaves are repositories, not products**, each carrying a repo-level CPE | Lets one erratum apply to exactly the repositories that shipped the build, and no others |
| 3 | **`mapping/cpe-repo-map.json`** — a new file mapping a host's system CPE to its repositories' CPEs | Produced nowhere today; this is the lookup a scanner needs |

CRLSA identity is unchanged (`CRLSA-YYYY:NNNN` already has the target form), so the CRLSAs here differ
from `main` only in `product_tree`.

---

## How a scanner uses this

```
1. Read the host's system CPE from /etc/system-release-cpe.
   →  cpe:2.3:o:ciq:rocky_linux_from_ciq_lts:9.6

2. Look that string up in mapping/cpe-repo-map.json, by EXACT STRING EQUALITY.
   →  [ cpe:2.3:o:ciq:rocky_linux_from_ciq:9.6:*:*:*:*:*:*:baseos,
        cpe:2.3:o:ciq:rocky_linux_from_ciq:9.6:*:*:*:*:*:*:appstream,
        cpe:2.3:o:ciq:rocky_linux_from_ciq:9.6:*:*:*:*:*:*:extras,
        cpe:2.3:o:ciq:rocky_linux_from_ciq:9.6:*:*:*:*:*:*:rlc_lts,
        cpe:2.3:o:ciq:rocky_linux_from_ciq:9.6:*:*:*:*:*:*:rlc_lts_supplemental ]

3. In an advisory, keep the product_tree leaves whose
   product_identification_helper.cpe is in that list. Discard the rest.

4. For each kept leaf, take its product_id and find the relationships whose
   relates_to_product_reference matches. Each gives a fixed package NEVRA.
   Compare against what is installed.
```

Step 3 is the whole point: a host only ever matches errata for repositories it actually has.

### Where to read the system CPE, and why it matters here

Use **`/etc/system-release-cpe`**. It contains the CPE string and nothing else, so it needs no
parsing beyond reading the file and trimming trailing whitespace.

`/etc/os-release` carries the same value in its `CPE_NAME` field, and the two were measured to agree
exactly on all four CIQ products booted for this work. But **`os-release` quotes the value and
`system-release-cpe` does not**:

```
/etc/os-release          CPE_NAME="cpe:2.3:o:ciq:rocky_linux_from_ciq_lts:9.6"
/etc/system-release-cpe  cpe:2.3:o:ciq:rocky_linux_from_ciq_lts:9.6
```

Because map keys are matched by **exact string equality**, a reader that takes the `os-release` value
without stripping the surrounding double quotes will match nothing at all — and will do so silently,
looking exactly like a host with no CIQ repositories. If you do read `os-release`, strip the quotes.

`/etc/system-release-cpe` was present on every product measured. It is an RHEL-family convention
rather than a cross-distribution one, so `os-release` is the sensible fallback if you need a single
code path across vendors.

---

## The two CPE conventions differ deliberately

This is the single most important thing to get right, and the two halves are **not** the same kind of
string.

| | Form | How to match |
|---|---|---|
| **Map keys** (system CPEs) | The **verbatim** contents of `/etc/system-release-cpe`. 6 colon-fields. **Not valid CPE 2.3.** | **Exact string equality.** Do not parse. |
| **Map values** and every `product_identification_helper.cpe` (repo CPEs) | Well-formed 13-field CPE 2.3 | CPE matching semantics |

Map keys are byte-for-byte what CIQ hosts actually write to `/etc/system-release-cpe` today. They stop after
`version`, omitting `update`, `edition`, `language`, `sw_edition`, `target_sw`, `target_hw` and
`other`, so they will **fail** a CPE 2.3 parser. That is expected, and matching them as opaque strings
is deliberate — inventing a normalization contract on both sides is more fragile than matching what is
really there.

### Both of these are interim. Please do not hard-code either.

- **Today:** 6-field keys, exact string equality.
- **Planned:** well-formed CPE 2.3 keys, matched with NISTIR 7696 superset semantics.

And note the transition changes the key's **value**, not merely its length. The target identity for
LTS is `rocky_linux_from_ciq_pro_lts`, where hosts currently emit `rocky_linux_from_ciq_lts` — so a
future key is *not* today's key with padding added. **Treat a map key as an opaque identifier
versioned with the map file, and re-read the map rather than deriving future keys from current ones.**

---

## Repository-level CPEs

```
cpe:2.3:o:ciq:{product}:{M.m}:*:*:*:*:*:*:{channel}
```

| Field | Value |
|---|---|
| `product` (3) | base distro identity — `rocky_linux_from_ciq`. **Never** a tier (`_pro`, `_plus`, `_lts`), never a repository name |
| `version` (4) | concrete `M.m`, taken from the version the repository **serves** |
| `sw_edition` (8) | `*` |
| `target_hw` (10) | **`*`** — see below |
| `other` (11) | the channel, with `-` → `_` (e.g. `rlc-lts` → `rlc_lts`) |

### Architecture is on the package, not on the channel

`target_hw` is always `*`. A channel spans every architecture, and the platform granularity here is
the **channel**, matching Red Hat, whose platform CPEs likewise carry a channel but no architecture
(`cpe:/o:redhat:enterprise_linux:8::baseos`).

Applicability is therefore decided by the **package NEVRA's own architecture**, which appears both in
the NEVRA and in the `architecture` branch of the `product_tree`:

- an `x86_64` host matches `x86_64` and `noarch` packages;
- `noarch` applies to every host;
- `src` appears as an `architecture` branch like any other and is **not installable content** — do not
  treat a `.src` NEVRA as something to compare against an installed package.

### Versions are concrete, never wildcarded

LTS 9.6's `baseos` and Pro 9.8's `baseos` are genuinely different repositories serving different
content. Concrete `M.m` keeps them distinct. A wildcarded version would make an erratum built against
current content appear applicable to a frozen LTS line.

**One documented exception:** `scn-9` carries a bare major (`…:9:*:…:scn`). SIG/Cloud Next is a rolling
major-scoped channel serving several minors concurrently, so it has no single served minor. This
breaks the concrete-`M.m` rule and is a known gap in CIQ's specification, not a typo.

---

## `product_id` conventions

```
platform leaf   rlc_lts-9.6                                        {channel}-{M.m}
package leaf    curl-0:8.20.0-1.el9_6_ciq.1.x86_64                 NEVRA, epoch always present
combined        rlc_lts-9.6:curl-0:8.20.0-1.el9_6_ciq.1.x86_64     {platform}:{package}
```

Two invariants you can rely on, both matching Red Hat's conventions:

1. **A platform `product_id` never contains a colon**, so a combined id always splits into its two
   parts on the **first** colon.
2. **A package NEVRA always carries an explicit epoch**, including `-0:`, so the package part always
   contains exactly one colon.

`split(':', 1)` on any `product_status.fixed` entry therefore recovers `(platform, nevra)` exactly.

---

## One build, several repositories

A source build can ship into more than one repository, and then it carries **several platform leaves**.
The kernel is the main case: CIQ cross-publishes a kernel build from its primary destination into
secondary ones.

`csaf/advisories/ciq/2026/ciqsa-2026-0004.json` is a real example — one kernel build in three channels,
with **different subsets of packages in each**:

| Channel | Packages |
|---|---|
| `rlc_lts-9.6` | 86 |
| `fips_compliant-9.6` | 38 |
| `ve1-9.6` | 8 |

So a relationship exists per *(channel that actually ships this RPM × RPM)* — **not** every package
against every channel. That document has 86 packages and 132 relationships.

**Some of those channels are not in the map.** `fips_compliant-9.6`, `ve1-9.6` and `scn-9` belong to
CIQ products outside the three covered here, so no key maps to them. That is correct and is the
mechanism working: an LTS 9.6 host matches only the `rlc_lts-9.6` leaf and ignores the others.

---

## Scoping: enabled-by-default repositories only

**The map lists only the repositories a product enables by default** — 5, 6 and 5 channels for the
three products. It does **not** list every repository defined on the host.

Each product also ships `/etc/yum.repos.d/` entries that are **defined but disabled**: `crb`,
`security`, `devel`, `plus`, `highavailability`, `nfv`, `rt`, `resilientstorage`, `sap`, `saphana`, and
a `-debug` variant of every channel. Basil, CIQ's product catalogue, lists 14/28/25 repositories for
these products where a booted host actually enables 6/7/6.

**Consequence you need to handle:** a customer who manually enables one of those channels needs its
repo CPE added, or a scanner will miss errata for packages from it. The same reasoning is why
`*-debuginfo` and `*-debugsource` packages are absent from these documents — they are served only from
`-debug` repositories, which are never enabled by default.

`coverage.defined_but_disabled_channels` in `cpe-repo-map.json` lists these per product.

---

## Contents

```
.
├── csaf/
│   └── advisories/
│       ├── ciq/2026/          # CIQSA — CIQ-built content
│       │   ├── ciqsa-2026-0001.json   curl,           23 CVEs, 1 channel
│       │   ├── ciqsa-2026-0002.json   sudo,            1 CVE,  1 channel
│       │   ├── ciqsa-2026-0003.json   python-urllib3,  5 CVEs, 1 channel, noarch
│       │   ├── ciqsa-2026-0004.json   kernel 9.6,     18 CVEs, 3 channels
│       │   └── ciqsa-2026-0005.json   kernel 9.8,      5 CVEs, 2 channels
│       └── rocky/2026/        # CRLSA — content mirrored from upstream Rocky
│           ├── crlsa-2026-42062.json  webkit2gtk3,    23 CVEs
│           ├── crlsa-2026-36879.json  tomcat,          2 CVEs, noarch
│           └── crlsa-2026-22551.json  mod_http2,       1 CVE
├── mapping/
│   └── cpe-repo-map.json      # system CPE → [repo CPEs]
└── README.md
```

**CIQSA vs CRLSA** is about who built the content, not about shape — both use the same `product_tree`
model. CRLSAs cover packages mirrored from upstream Rocky; CIQSAs cover packages CIQ builds. Note
`ciqsa-2026-0005.json` is a CIQSA even though it rebuilds an upstream kernel, because it ships into
`rlc_core`, a CIQ-built repository.

### Products covered

| System CPE (map key) | Product | Channels |
|---|---|---|
| `cpe:2.3:o:ciq:rocky_linux_from_ciq_lts:9.6` | Rocky Linux from CIQ LTS 9.6 | 5 |
| `cpe:2.3:o:ciq:rocky_linux_from_ciq_pro:9.8` | Rocky Linux from CIQ Pro 9.8 | 6 |
| `cpe:2.3:o:ciq:rocky_linux_from_ciq_plus:9.8` | Rocky Linux from CIQ Plus 9.8 | 5 |

Pro and Plus differ by exactly one repository, `rlc_pro`. Every other channel is **byte-identical**
between them, which is why the three CRLSAs here apply to both products through the same
`appstream-9.8` leaf. That aggregation is real, not constructed.

### Not present, deliberately

- **`mapping/cpe-product-keys.json`**, which exists on `main`, maps a system CPE to a CIQ *product
  key* (`lts-9.6`). It is omitted because the new advisory shape has no product-slug identity — nothing
  here references a product key. It is not superseded by `cpe-repo-map.json`; the two answer different
  questions. Be aware that its keys on `main` are padded to 13 fields and so match no real host CPE.
- **`provider-metadata.json`, `index.txt`, `changes.csv`** — CSAF distribution metadata. Not present on
  `main` either; generating them is outstanding CIQ work.
- **VEX documents** for these CVEs are not included in this branch yet.

---

## What is real and what is not

**Real, measured:**

- **System CPEs** — read off booted VMs of each of the three products, byte-for-byte.
- **Enabled repository sets** — from `dnf repolist --enabled` on those hosts.
- **Package names and NEVRAs**, every architecture including `aarch64` and `src` — from live CIQ depot
  repository metadata. No architecture variant was produced by editing another's string.
- **Which repository serves which package** — from that same live metadata.
- **CVE identifiers, CVSS vectors, CWEs and descriptions** — from CIQ Errata Management.
- **The Pro/Plus aggregation** — those repositories genuinely share byte-identical ids.
- **The kernel's multi-repository delivery** — verified against depot; 41 of 88 kernel builds examined
  span more than one channel.

**Constructed for illustration:**

- **Advisory numbering.** `CIQSA-2026:0001`–`0005` are assigned for this branch.
- **The pairing of a CVE set to a specific build** may not reflect a real published erratum.
  `ciqsa-2026-0005.json` is the clearest case: CIQ Errata Management holds no data for Pro/Plus, so its
  CVEs are borrowed from the advisory for the upstream Rocky kernel that this build rebuilds.
- **Repository-level CPEs** are not produced by any CIQ system today; they are constructed here to the
  intended specification.

**Known gaps:**

- Only 3 of roughly 48 CIQ products are represented.
- A **rolling product that has not been updated reports a minor behind its repositories** — measured on
  Pro Hardened, which shipped reporting 9.7 while serving 9.8. Such a host's system CPE will not be in
  the map. None of the three products here is in that state.
- Several channels in the map carry **no sample advisory** (`baseos`, `extras`, `rlc_core`,
  `rlc_supplemental`, `rlc_pro`, `rlc_lts_supplemental`). The map describes each product's real
  repository set; the advisories are a deliberately small subset. Absence is not breakage.
- `aarch64` package data is real, but no `aarch64` host was booted, so the *system* CPE and enabled
  repository set for that architecture are unverified.

---

## Known non-compliance

`CIQSA-YYYY:NNNN` is rejected by CIQ's own CSAF validator, which still expects the older
`CIQSA-<product_slug>-YYYY:NNNN` form. This is a finding against CIQ's production tooling, not a defect
in these documents, and it is the **only** schema complaint they produce. The three CRLSAs validate
cleanly with no errors at all.
