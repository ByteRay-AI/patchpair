# PatchPair

Builds a dataset of **before/after Windows kernel-mode binary pairs** from Microsoft's Patch Tuesday security updates, each annotated with the CVEs (and CWE / impact / CVSS) the update addresses.

For every KB that patches a kernel component, the tool acquires the patched binary and its closest prior version, and stores them together with CVE and KB metadata — ready for binary diffing, vulnerability research, or training data.

## What it does

1. Queries the **MSRC CVRF API** for a month's security advisories.
2. Keeps CVEs whose titles name a kernel-mode component (`kernel`, `win32k`, `afd`, `clfs`, `ntfs`, `tcpip`, `ndis`, `http.sys`, …), enriching each with its **CWE**, **impact**, and **CVSS** base score.
3. Acquires the **patched** binary, trying in order:
   - **delta MSU** → parse `.mum` manifests → resolve the exact version on WinBIndex
   - **full MSU** → take PEs straight from the cabinet (old KBs), or — for modern cabinets that ship only **PA30 deltas** — use the `.mum` manifests and the `*.cix.xml` container index to resolve the version on WinBIndex
   - **WinBIndex by KB number**, when the catalog no longer hosts the KB (common for KBs older than ~3 years)
4. Selects the **previous** version:
   - **Tier 0** — exact source match from the PSFX `*.cix.xml` index (the precise binary the PA30 delta was applied to)
   - **Tier 1** — same Windows version (e.g. both from `10-1809`)
   - **Tier 2** — same version branch (`major.minor.build`)
   - **Tier 3** — any strictly older distinct version
5. Downloads both binaries from the **Microsoft Symbol Server** (SHA256-validated; PA30 deltas the server occasionally returns are rejected).
6. Attributes the **relevant CVE(s)** to each binary by component name and writes a pair folder with a `metadata.json`. Pairs are written incrementally — one binary at a time — so an interrupt loses at most the binary in flight.

## Output layout

```
pairs/
  2024/
    afd_44f548e3/
      patched/afd.sys
      prev/afd_10_0_17763_2183.sys
      metadata.json
    clfs_0a1b2c3d/
      ...
```

Each `metadata.json` records:

```jsonc
{
  "binary": "afd.sys",
  "kb": "KB5041571",
  "release_date": "2024-08-13",
  "relevant_cves": [                       // CVEs attributed to THIS binary
    {
      "id": "CVE-2024-38193",
      "title": "Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability",
      "cwe": [{ "id": "CWE-416", "name": "Use After Free" }],
      "impact": "Elevation of Privilege",
      "cvss": 7.8
    }
  ],
  "cve_attribution": "title component match",
  "cves": [ /* all enriched CVEs for the KB, as a fallback */ ],
  "patched": { "version": "10.0.17763.6189", "sha256": "…", "file": "patched/afd.sys" },
  "prev": {
    "version": "10.0.17763.5830", "sha256": "…",
    "kb_numbers": ["KB5037765"], "win_versions": ["10-1809"],
    "file": "prev/afd_10_0_17763_5830.sys",
    "selection_tier": 1,
    "selection_tier_description": "same Windows version (e.g. both from '10-1809')"
  }
}
```

## Install

```bash
uv venv
uv pip install -r requirements.txt
sudo apt install cabextract   # Linux/macOS — not needed on Windows
```

## Usage

```bash
# Single year
python patchpair.py --year 2024

# Year range
python patchpair.py --year-from 2022 --year-to 2024

# Single KB (skips MSRC lookup)
python patchpair.py --kb KB5041571

# Preview matching KBs and CVEs without downloading anything
python patchpair.py --year 2024 --dry-run

# Custom output / scratch directories; keep intermediate files for inspection
python patchpair.py --year 2024 --output ./pairs --work-dir ./work --keep
```

**Scale:** a full year of kernel KBs can mean tens of MSU packages (50–600 MB each) and a few GB of scratch space. Runs are resumable — an existing pair folder is skipped without re-downloading.

## Inspiration

Inspired by [post-patch-postmortem](https://github.com/joshterrill/post-patch-postmortem), which does binary diffing of Windows patches.

## Data sources

| Source | Purpose |
|--------|---------|
| [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v2.0/) | CVE titles, CWE, impact, CVSS, and KB numbers per Patch Tuesday |
| [Microsoft Update Catalog](https://www.catalog.update.microsoft.com) | KB package (MSU / delta) download |
| [WinBIndex](https://winbindex.m417z.com) | Binary version history and symbol-server metadata |
| [Microsoft Symbol Server](https://msdl.microsoft.com/download/symbols) | Patched and previous binary download |
