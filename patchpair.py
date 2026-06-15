#!/usr/bin/env python3
"""
patchpair — before/after Windows kernel binary pairs from Patch Tuesday.

For a given year (or year range, or a single KB) this builds a dataset of
"patched vs previous" Windows kernel-mode binaries together with the CVEs each
update addresses:

  1. Query the MSRC CVRF API for a month's security advisories.
  2. Keep CVEs whose titles name a kernel-mode component (kernel, win32k, afd,
     clfs, ntfs, tcpip, ...), enriched with CWE, impact and CVSS base score.
  3. Acquire the patched binary, trying in order:
       a. delta MSU  -> .mum manifests        -> resolve version on WinBIndex
       b. full MSU   -> PEs from the cabinet, or .mum / CIX index -> WinBIndex
       c. WinBIndex by KB number, when the catalog no longer hosts the KB
     Modern cabinets carry only PA30 deltas (not full PEs); the companion
     *.cix.xml gives the exact patched/previous SHA256 pair when present.
  4. Pick the closest previous version (CIX exact source match, else a 3-tier
     heuristic) and download both binaries from the Microsoft Symbol Server.
  5. Attribute the relevant CVE(s) to each binary by component name, and write a
     pair folder with a metadata.json.

Output layout:
  <output>/<year>/<binary_stem>_<sha8>/
      patched/<binary>
      prev/<versioned_binary>
      metadata.json

Usage:
  python patchpair.py --year 2024
  python patchpair.py --year-from 2023 --year-to 2024
  python patchpair.py --kb KB5034122          # single KB, skip MSRC lookup
  python patchpair.py --year 2024 --dry-run   # list KBs without downloading

Requirements:
  uv pip install -r requirements.txt          # httpx, beautifulsoup4, lxml, rich, pefile
  sudo apt install cabextract                 # Linux/macOS (not needed on Windows)
  export VT_API_KEY=...                        # optional: VirusTotal fallback for
                                               #   binaries the symbol server dropped

Scale: a full year of kernel KBs can mean tens of MSU packages (50-600 MB each)
and a few GB of scratch space. --dry-run previews what would be processed.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table


# --- Constants ---

# API / download endpoints
MSRC_API       = "https://api.msrc.microsoft.com/cvrf/v2.0"
WINBINDEX_BASE = "https://winbindex.m417z.com"
MSDL_BASE      = "https://msdl.microsoft.com/download/symbols"
VT_FILE_API    = "https://www.virustotal.com/api/v3/files"  # /{sha256}/download
CATALOG_SEARCH = "https://www.catalog.update.microsoft.com/Search.aspx"
CATALOG_DIALOG = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"

# HTTP headers
MSRC_HEADERS = {"User-Agent": "patchpair/1.0", "Accept": "application/json"}
HTTP_HEADERS  = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept": "*/*"}
CATALOG_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Kernel-component detection: .sys is always kernel-mode; these specific .exe/.dll
# are kernel images / HAL too.
KERNEL_BY_NAME = frozenset({
    "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe",
    "hal.dll", "halmacpi.dll", "halacpi.dll",
    "win32k.sys", "win32kbase.sys", "win32kfull.sys",
})
BINARY_EXTS = frozenset({".sys", ".exe", ".dll", ".drv"})

# Regexes
_KERNEL_RE = re.compile(  # CVE titles indicating kernel-mode involvement
    r"kernel|win32k|\bndis\b|\bdriver\b|ntfs|\bclfs\b|\bafd\b|http\.sys|tcp[/ ]ip"
    r"|\bsmb\b|named pipe|hyper.v|hypervisor|securekernel|\bhal\b",
    re.IGNORECASE,
)
_HASH_SUFFIX_RE = re.compile(r"_[a-f0-9]{8}(\.[a-zA-Z0-9]+)$")  # foo_1a2b3c4d.sys -> foo.sys
_WIN_VER_KEY_RE = re.compile(r"^\d{1,2}-[\w.]+$")               # WinBIndex key: 10-1809, 11-22H2
_SHA256_RE      = re.compile(r"^[a-f0-9]{64}$")

# XML namespaces
_NS_CIX  = "urn:ContainerIndex"                  # PSFX container index (*.cix.xml)
_NS_ASM3 = "urn:schemas-microsoft-com:asm.v3"    # .mum assembly manifests
_NS_DSIG = "http://www.w3.org/2000/09/xmldsig#"

# Previous-version selection tiers (see find_prev).
_TIER_DESCRIPTIONS = {
    1: "same Windows version (e.g. both from '10-1809')",
    2: "same version branch (major.minor.build)",
    3: "any strictly older distinct version",
}

# Component package name substring -> binary filename.  Used when a delta MSU's
# outer update.mum only has <component> assemblyIdentity elements (no <file>
# children with DigestValue) — common in older/PSFX packages.  Keys are lowercase
# substrings matched against the component "name" attribute.
_COMPONENT_BINARY_MAP: list[tuple[str, str]] = [
    # kernel / HAL
    ("os-kernel",        "ntoskrnl.exe"),
    ("ntkrnlmp",         "ntoskrnl.exe"),
    ("ntkrnlpa",         "ntkrnlpa.exe"),
    ("hal-legacy",       "hal.dll"),
    ("halmacpi",         "halmacpi.dll"),
    ("halacpi",          "halacpi.dll"),
    # networking
    ("tcpip",            "tcpip.sys"),
    ("netio",            "netio.sys"),
    ("ndis",             "ndis.sys"),
    ("afd",              "afd.sys"),
    ("http-",            "http.sys"),         # http-driver, http-protocol…
    ("smb",              "mrxsmb.sys"),
    ("smbminiport",      "mrxsmb20.sys"),
    ("mup",              "mup.sys"),
    # filesystem / storage
    ("ntfs",             "ntfs.sys"),
    ("clfs",             "clfs.sys"),
    ("fastfat",          "fastfat.sys"),
    ("cdfs",             "cdfs.sys"),
    ("refs",             "refs.sys"),
    ("storport",         "storport.sys"),
    ("classpnp",         "classpnp.sys"),
    # graphics
    ("win32k-base",      "win32kbase.sys"),
    ("win32k-full",      "win32kfull.sys"),
    ("win32k",           "win32k.sys"),
    ("dxgkrnl",          "dxgkrnl.sys"),
    # security / hypervisor
    ("securekernel",     "securekernel.exe"),
    ("ci-",              "ci.dll"),
    ("cng",              "cng.sys"),
    ("ksecdd",           "ksecdd.sys"),
    ("lsass",            "lsass.exe"),
    # HV / virtualisation
    ("hvix64",           "hvix64.exe"),
    ("hvax64",           "hvax64.exe"),
    ("hv-",              "hv.exe"),
]

# CVE title pattern -> kernel binary filename(s).  MSRC titles use friendly
# component names ("Ancillary Function Driver for WinSock", "Common Log File
# System Driver"), so patterns match those as well as bare file/abbrev names.
# Used both to (a) pick download candidates when the catalog lacks a KB, and
# (b) attribute a CVE to a specific patched binary in metadata.
_CVE_BINARY_HINTS: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"\bafd\b|ancillary function driver", re.I),     ["afd.sys"]),
    (re.compile(r"win32k|win32", re.I),                          ["win32k.sys", "win32kbase.sys", "win32kfull.sys"]),
    (re.compile(r"\bntfs\b", re.I),                              ["ntfs.sys"]),
    (re.compile(r"\bclfs\b|common log file system", re.I),       ["clfs.sys"]),
    (re.compile(r"tcp.?ip|tcpip", re.I),                         ["tcpip.sys"]),
    (re.compile(r"\bnetbt\b|netbios", re.I),                     ["netbt.sys"]),
    (re.compile(r"http\.sys|http\s+protocol|http\.?sys", re.I),  ["http.sys"]),
    (re.compile(r"\bsmb\b|message block|mrxsmb", re.I),          ["mrxsmb.sys", "mrxsmb20.sys"]),
    (re.compile(r"\bndis\b", re.I),                              ["ndis.sys", "netio.sys"]),
    (re.compile(r"\bdwm\b|desktop window manager", re.I),        ["dwmcore.dll"]),
    (re.compile(r"\bcsrss\b|client server runtime", re.I),       ["csrss.exe"]),
    (re.compile(r"\bdxgkrnl\b|directx|graphics kernel", re.I),   ["dxgkrnl.sys", "dxgmms2.sys"]),
    (re.compile(r"storage|storport|\bstorvsc\b", re.I),          ["storport.sys", "storvsc.sys"]),
    (re.compile(r"\bfastfat\b|fat\b", re.I),                     ["fastfat.sys"]),
    (re.compile(r"cloud files|\bcldflt\b", re.I),                ["cldflt.sys"]),
    (re.compile(r"\bcng\b|cryptographic|crypto", re.I),          ["cng.sys", "ksecdd.sys"]),
    (re.compile(r"hyper.?v|hypervisor", re.I),                   ["hvix64.exe", "hvax64.exe"]),
    (re.compile(r"secure.?kernel", re.I),                        ["securekernel.exe"]),
    (re.compile(r"\bhal\b", re.I),                               ["hal.dll", "halmacpi.dll"]),
    (re.compile(r"named\s+pipe|\bnpfs\b", re.I),                 ["npfs.sys"]),
    (re.compile(r"\bkernel\b", re.I),                            ["ntoskrnl.exe"]),
]

console = Console()

# Startup banner (ASCII art tool name + small attribution line).
_BANNER = r"""
██████╗  █████╗ ████████╗ ██████╗██╗  ██╗██████╗  █████╗ ██╗██████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║██╔══██╗
██████╔╝███████║   ██║   ██║     ███████║██████╔╝███████║██║██████╔╝
██╔═══╝ ██╔══██║   ██║   ██║     ██╔══██║██╔═══╝ ██╔══██║██║██╔══██╗
██║     ██║  ██║   ██║   ╚██████╗██║  ██║██║     ██║  ██║██║██║  ██║
╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
"""


def _print_banner() -> None:
    console.print(f"[bold cyan]{_BANNER}[/bold cyan]", highlight=False)
    console.print("  by Argus Systems\n", style="dim")


# --- Data models ---

@dataclasses.dataclass
class CVEInfo:
    cve_id: str
    title: str
    cwe: list[dict] = dataclasses.field(default_factory=list)  # [{"id":"CWE-416","name":"Use After Free"}]
    impact: str = ""        # Threat "Impact", e.g. "Elevation of Privilege"
    cvss: Optional[float] = None  # CVSS v3 base score


@dataclasses.dataclass
class KBMeta:
    kb: str
    release_date: Optional[str]  # "YYYY-MM-DD"
    cves: list[CVEInfo] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class MumEntry:
    filename: str   # clean lowercase name, e.g. "tcpip.sys"
    version: str    # from assemblyIdentity, e.g. "10.0.16299.192"
    sha256: str     # hex SHA256 from DigestValue (empty string if absent)


@dataclasses.dataclass
class CixEntry:
    filename: str        # clean lowercase basename, e.g. "afd.sys"
    target_sha256: str   # SHA256 of the patched PE (lowercase hex)
    source_sha256: str   # SHA256 of the source/prev PE (lowercase hex)


@dataclasses.dataclass
class BinVersion:
    filename: str
    version: str
    sha256: str
    urls: list[str]
    release_date: Optional[datetime]
    kb_numbers: list[str]
    win_versions: set[str]  # e.g. {"10-1809", "10-21H1"}
    last_error: str = ""    # populated by download_binary on failure


@dataclasses.dataclass
class PatchedJob:
    """One patched binary to turn into a pair. Exactly one source is set:
      path — a PE already on disk (extracted from the MSU cabinet)
      bv   — a WinBIndex version to fetch from the symbol server
    """
    clean: str                       # lowercase filename, e.g. "afd.sys"
    path: Optional[Path] = None
    bv: Optional[BinVersion] = None


# --- Utilities ---

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_version(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))


def _parse_dt(value) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    if re.fullmatch(r"\d+", s):
        ts = float(s)
        if ts > 1e11:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError):
            return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _dt_key(dt: Optional[datetime]) -> float:
    if dt is None:
        return float("-inf")
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _pe_version_fixedfileinfo(path: Path) -> Optional[str]:
    """
    Locates the VS_FIXEDFILEINFO structure (signature 0xFEEF04BD) in the version
    resource and reads dwFileVersionMS/LS. Used as a fallback when pefile is not
    installed so the patched/unpatched ordering stays reliable regardless of env.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    i = data.find(b"\xbd\x04\xef\xfe")  # VS_FIXEDFILEINFO dwSignature, little-endian
    if i == -1 or i + 16 > len(data):
        return None
    import struct
    ms, ls = struct.unpack_from("<II", data, i + 8)  # +8 dwFileVersionMS, +12 dwFileVersionLS
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def _pe_version(path: Path) -> Optional[str]:
    # Prefer pefile when present; otherwise fall back to the stdlib scan so the
    # patched/unpatched labels are never wrong just because pefile is missing.
    try:
        import pefile  # type: ignore
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
            fi = pe.VS_FIXEDFILEINFO[0]
            ms, ls = fi.FileVersionMS, fi.FileVersionLS
            pe.close()
            return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        pe.close()
    except ImportError:
        pass
    except Exception:
        pass
    return _pe_version_fixedfileinfo(path)


def _normalize_kb(kb: str) -> str:
    kb = kb.strip().upper()
    return kb if kb.startswith("KB") else f"KB{kb}"


def _is_kernel_component(name: str) -> bool:
    n = name.lower()
    return n.endswith(".sys") or n in KERNEL_BY_NAME


def _strip_hash_suffix(filename: str) -> str:
    return _HASH_SUFFIX_RE.sub(r"\1", filename.lower())


def _path_arch(path: Path) -> Optional[str]:
    s = str(path).lower()
    if "arm64" in s or "aarch64" in s:
        return "arm64"
    if "amd64" in s or "_x64" in s or "-x64" in s or "\\x64\\" in s or "/x64/" in s:
        return "x64"
    if "x86" in s or "i386" in s or "wow64" in s:
        return "x86"
    return None


def _is_pe(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _parse_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


# --- MSRC CVRF API ---

def msrc_update_ids(year_from: int, year_to: int) -> list[tuple[str, str]]:
    """Return sorted list of (update_id, release_date) for months in [year_from, year_to]."""
    with httpx.Client(timeout=30.0) as c:
        r = c.get(f"{MSRC_API}/updates", headers=MSRC_HEADERS)
        r.raise_for_status()

    out: list[tuple[str, str]] = []
    for item in r.json().get("value", []):
        uid = item.get("ID", "")
        release = (item.get("InitialReleaseDate", "") or "")[:10]
        try:
            dt = datetime.strptime(uid, "%Y-%b")
        except ValueError:
            continue
        if year_from <= dt.year <= year_to:
            out.append((uid, release))
    return sorted(out)


def msrc_kernel_kbs(update_id: str) -> dict[str, KBMeta]:
    """
    Fetch CVRF document for update_id and return {kb: KBMeta}
    for CVEs whose titles match the kernel component pattern.
    Each CVE is enriched with CWE, impact and CVSS base score.
    """
    with httpx.Client(timeout=60.0) as c:
        r = c.get(f"{MSRC_API}/cvrf/{update_id}", headers=MSRC_HEADERS)
        r.raise_for_status()
        doc = r.json()

    release_date: str = ""
    rd = (doc.get("DocumentTracking") or {}).get("InitialReleaseDate", "")
    if rd:
        release_date = rd[:10]

    kb_map: dict[str, KBMeta] = {}

    for vuln in doc.get("Vulnerability", []):
        title_raw = vuln.get("Title", {})
        title = title_raw.get("Value", "") if isinstance(title_raw, dict) else str(title_raw)
        cve_id = vuln.get("CVE", "")

        if not _KERNEL_RE.search(title):
            continue

        # Enrichment shared by every KB this CVE maps to.
        cwe = [
            {"id": w.get("ID", ""), "name": w.get("Value", "")}
            for w in (vuln.get("CWE") or [])
            if isinstance(w, dict) and w.get("ID")
        ]
        # Threat Type is an integer enum in CVRF v2.0; 0 == Impact
        # (e.g. "Elevation of Privilege", "Remote Code Execution").
        impact = ""
        for t in vuln.get("Threats", []):
            if t.get("Type") == 0:
                d = t.get("Description") or {}
                impact = d.get("Value", "") if isinstance(d, dict) else str(d)
                if impact:
                    break
        cvss: Optional[float] = None
        for css in vuln.get("CVSSScoreSets", []):
            base = css.get("BaseScore")
            if base is not None:
                try:
                    cvss = float(base)
                    break
                except (TypeError, ValueError):
                    pass

        for rem in vuln.get("Remediations", []):
            # Primary: KBArticle.ID
            kb_article = rem.get("KBArticle")
            if isinstance(kb_article, dict) and kb_article.get("ID"):
                kb = _normalize_kb(kb_article["ID"])
            else:
                # Fallback: Description.Value when it's a bare KB number
                desc = rem.get("Description") or {}
                val = (desc.get("Value", "") if isinstance(desc, dict) else str(desc)).strip()
                if not re.fullmatch(r"\d{6,8}", val):
                    continue
                kb = f"KB{val}"

            if kb not in kb_map:
                kb_map[kb] = KBMeta(kb=kb, release_date=release_date)
            if cve_id:
                known = {c.cve_id for c in kb_map[kb].cves}
                if cve_id not in known:
                    kb_map[kb].cves.append(
                        CVEInfo(cve_id=cve_id, title=title, cwe=cwe, impact=impact, cvss=cvss)
                    )

    return kb_map


def msrc_cve_kbs(cve_id: str) -> dict[str, KBMeta]:
    """
    Find all KBs that fix a given CVE by scanning the monthly CVRF documents
    for the CVE's year. No kernel-component title filter is applied — the
    caller already selected the CVE explicitly.
    """
    m = re.match(r"CVE-(\d{4})-", cve_id, re.IGNORECASE)
    if not m:
        raise ValueError(f"invalid CVE ID format: {cve_id}")
    year = int(m.group(1))

    update_ids = msrc_update_ids(year, year)
    kb_map: dict[str, KBMeta] = {}

    with httpx.Client(timeout=60.0) as c:
        for uid, _ in update_ids:
            console.print(f"  [dim]scanning {uid}...[/dim]")
            try:
                r = c.get(f"{MSRC_API}/cvrf/{uid}", headers=MSRC_HEADERS)
                r.raise_for_status()
                doc = r.json()
            except Exception as e:
                console.print(f"  [yellow]warning: {uid}: {e}[/yellow]")
                continue

            release_date = (doc.get("DocumentTracking") or {}).get("InitialReleaseDate", "")[:10]

            for vuln in doc.get("Vulnerability", []):
                vid = vuln.get("CVE", "")
                if vid.upper() != cve_id.upper():
                    continue

                title_raw = vuln.get("Title", {})
                title = title_raw.get("Value", "") if isinstance(title_raw, dict) else str(title_raw)

                cwe = [
                    {"id": w.get("ID", ""), "name": w.get("Value", "")}
                    for w in (vuln.get("CWE") or [])
                    if isinstance(w, dict) and w.get("ID")
                ]
                impact = ""
                for t in vuln.get("Threats", []):
                    if t.get("Type") == 0:
                        d = t.get("Description") or {}
                        impact = d.get("Value", "") if isinstance(d, dict) else str(d)
                        if impact:
                            break
                cvss: Optional[float] = None
                for css in vuln.get("CVSSScoreSets", []):
                    base = css.get("BaseScore")
                    if base is not None:
                        try:
                            cvss = float(base)
                            break
                        except (TypeError, ValueError):
                            pass

                for rem in vuln.get("Remediations", []):
                    kb_article = rem.get("KBArticle")
                    if isinstance(kb_article, dict) and kb_article.get("ID"):
                        kb = _normalize_kb(kb_article["ID"])
                    else:
                        desc = rem.get("Description") or {}
                        val = (desc.get("Value", "") if isinstance(desc, dict) else str(desc)).strip()
                        if not re.fullmatch(r"\d{6,8}", val):
                            continue
                        kb = f"KB{val}"

                    if kb not in kb_map:
                        kb_map[kb] = KBMeta(kb=kb, release_date=release_date)
                    known = {c.cve_id for c in kb_map[kb].cves}
                    if vid not in known:
                        kb_map[kb].cves.append(
                            CVEInfo(cve_id=vid, title=title, cwe=cwe, impact=impact, cvss=cvss)
                        )

            time.sleep(0.3)

    return kb_map


def msrc_bulletin_kbs(bulletin_id: str) -> dict[str, KBMeta]:
    """
    Find KBs for an MS Security Bulletin (e.g. MS16-014) by:
      1. Scraping the CVE list from learn.microsoft.com (works for pre-2017 bulletins)
      2. Calling msrc_cve_kbs() for the first CVE found

    Hacky but works — no official API maps MS bulletins to KBs for older bulletins.
    """
    m = re.match(r"MS(\d{2})-(\d+)$", bulletin_id, re.IGNORECASE)
    if not m:
        raise ValueError(f"invalid MS bulletin format (expected e.g. MS16-014): {bulletin_id}")
    year = 2000 + int(m.group(1))

    url = f"https://learn.microsoft.com/en-us/security-updates/securitybulletins/{year}/{bulletin_id.lower()}"
    console.print(f"  [dim]fetching CVEs from {url}[/dim]")

    with httpx.Client(timeout=30.0, follow_redirects=True) as c:
        r = c.get(url, headers={"User-Agent": "patchpair/1.0"})
        r.raise_for_status()

    cves = sorted(set(re.findall(r"CVE-\d{4}-\d+", r.text, re.IGNORECASE)),
                  key=lambda x: x.upper())
    if not cves:
        console.print(f"  [red]no CVEs found on bulletin page[/red]")
        return {}

    console.print(f"  CVEs in {bulletin_id}: {', '.join(cves)}")
    # All CVEs in a bulletin are fixed by the same KB package — scan just the first one.
    return msrc_cve_kbs(cves[0])


# --- CVE -> binary attribution ---

def _cve_candidate_files(cves: list[CVEInfo]) -> list[str]:
    """Return a deduplicated list of candidate binary filenames derived from CVE titles."""
    seen: set[str] = set()
    out: list[str] = []
    for cve in cves:
        for pattern, filenames in _CVE_BINARY_HINTS:
            if pattern.search(cve.title):
                for fn in filenames:
                    if fn not in seen:
                        seen.add(fn)
                        out.append(fn)
    return out


def _cves_for_binary(clean: str, cves: list[CVEInfo]) -> list[CVEInfo]:
    """Heuristically attribute CVEs to a patched binary via component keywords in
    the CVE title.  Returns the subset of cves whose title maps to `clean`.

    Best-effort only: MSRC has no public binary→CVE mapping, so this relies on the
    title naming the component.  Empty result means no confident attribution.
    """
    out: list[CVEInfo] = []
    for cve in cves:
        for pattern, filenames in _CVE_BINARY_HINTS:
            if clean in filenames and pattern.search(cve.title):
                out.append(cve)
                break
    return out


def _cve_to_dict(cve: CVEInfo) -> dict:
    """Serialize a CVEInfo (with CWE/impact/CVSS enrichment) for metadata.json."""
    return {
        "id": cve.cve_id,
        "title": cve.title,
        "cwe": cve.cwe,
        "impact": cve.impact,
        "cvss": cve.cvss,
    }


# --- Microsoft Update Catalog ---

def _catalog_raw_entries(kb: str) -> list[dict]:
    """Fetch all catalog entries for kb, each tagged with arch and delta flag."""
    with httpx.Client(timeout=60.0, follow_redirects=True) as c:
        r = c.get(CATALOG_SEARCH, params={"q": kb}, headers=CATALOG_HEADERS)
        r.raise_for_status()

    soup = BeautifulSoup(r.text, "lxml")
    table = soup.find("table", id="ctl00_catalogBody_updateMatches")
    if not table:
        return []

    entries: list[dict] = []
    for row in table.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) < 5:
            continue
        inp = row.find("input", {"class": "flatBlueButtonDownload"})
        if not inp:
            continue
        update_id = inp.get("id", "").replace("_", "-")
        title_tag = cells[1].find("a")
        title = title_tag.get_text(strip=True) if title_tag else cells[1].get_text(strip=True)
        tl = title.lower()
        arch = (
            "arm64" if "arm64" in tl
            else "x64" if ("x64" in tl or "64-bit" in tl)
            else "x86" if ("x86" in tl or "32-bit" in tl)
            else None
        )
        entries.append({"update_id": update_id, "title": title, "arch": arch, "delta": "delta" in tl})
    return entries


def catalog_search_kb(kb: str) -> list[dict]:
    """Return full (non-delta) x64 entries for kb, for full-MSU extraction path.
    Returns empty list if only delta packages exist — deltas can't be used for PE extraction."""
    entries = _catalog_raw_entries(kb)
    x64_full = [e for e in entries if e["arch"] == "x64" and not e["delta"]]
    if x64_full:
        return x64_full
    return [e for e in entries if not e["delta"]]


def catalog_search_delta(kb: str) -> list[dict]:
    """Return x64 delta entries for kb, for the .mum-based download path."""
    entries = _catalog_raw_entries(kb)
    x64_delta = [e for e in entries if e["arch"] == "x64" and e["delta"]]
    if x64_delta:
        return x64_delta
    return [e for e in entries if e["delta"]]


def _catalog_download_url(update_id: str) -> Optional[str]:
    payload = {"updateIDs": json.dumps([{"uidInfo": update_id, "updateID": update_id}])}
    with httpx.Client(timeout=60.0, follow_redirects=True) as c:
        c.get("https://www.catalog.update.microsoft.com", headers=CATALOG_HEADERS)
        r = c.post(
            CATALOG_DIALOG,
            data=payload,
            headers={**CATALOG_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        for pat in [
            r"https?://[^'\"]+\.msu",
            r"https?://[^'\"]+\.cab",
            r"https?://(?:catalog\.s\.)?download\.windowsupdate\.com/[^'\"]+",
        ]:
            m = re.search(pat, r.text)
            if m:
                return m.group(0)
    return None


def download_kb_package(kb: str, dest_dir: Path) -> Optional[Path]:
    """Download the x64 MSU/CAB for kb into dest_dir. Returns the local path."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    existing = list(dest_dir.glob(f"*{kb}*.msu")) + list(dest_dir.glob(f"*{kb}*.cab"))
    if existing:
        console.print(f"  [dim]cached: {existing[0].name}[/dim]")
        return existing[0]

    entries = catalog_search_kb(kb)
    if not entries:
        console.print(f"  [yellow]no catalog results for {kb}[/yellow]")
        return None

    for entry in entries:
        url = _catalog_download_url(entry["update_id"])
        if not url:
            continue
        filename = url.split("/")[-1].split("?")[0]
        if not filename.lower().endswith((".msu", ".cab")):
            filename = f"{kb}_{entry['update_id'][:8]}.msu"
        out = dest_dir / filename
        tmp = out.with_suffix(".part")
        console.print(f"  downloading {filename}...")
        try:
            with httpx.Client(timeout=600.0, follow_redirects=True) as c:
                with c.stream("GET", url, headers=HTTP_HEADERS) as r:
                    r.raise_for_status()
                    total = int(r.headers.get("content-length", 0))
                    with Progress(
                        TextColumn("  [cyan]{task.fields[fn]}"),
                        BarColumn(bar_width=40),
                        "[progress.percentage]{task.percentage:>3.0f}%",
                        DownloadColumn(),
                        TimeRemainingColumn(),
                        console=console,
                    ) as prog:
                        task = prog.add_task("dl", fn=filename, total=total or None)
                        with open(tmp, "wb") as f:
                            for chunk in r.iter_bytes(8192):
                                f.write(chunk)
                                prog.update(task, advance=len(chunk))
            tmp.replace(out)
            return out
        except Exception as e:
            tmp.unlink(missing_ok=True)
            console.print(f"  [red]download error: {e}[/red]")

    return None


# --- MSU / CAB extraction ---

def _cab_tool() -> tuple[str, list[str]]:
    if platform.system().lower() == "windows":
        return "expand", ["-F:*"]
    if shutil.which("cabextract"):
        return "cabextract", ["-q"]
    raise RuntimeError(
        "cabextract not found.\n"
        "  Ubuntu/Debian: sudo apt install cabextract\n"
        "  macOS:         brew install cabextract"
    )


def _extract_cab(cab: Path, out: Path) -> bool:
    out.mkdir(parents=True, exist_ok=True)
    cmd, flags = _cab_tool()
    args = ([cmd] + flags + [str(cab), str(out)]) if cmd == "expand" \
        else ([cmd] + flags + ["-d", str(out), str(cab)])
    return subprocess.run(args, capture_output=True).returncode == 0


def _extract_nested_cabs(directory: Path, depth: int = 5) -> None:
    """MSU packages nest: MSU → CAB → CAB → PSFX.cab → binaries."""
    if depth <= 0:
        return
    for cab in list(directory.rglob("*.cab")):
        marker = cab.parent / f".done_{cab.stem}"
        if marker.exists():
            continue
        out = cab.parent / f"_x_{cab.stem}"
        if _extract_cab(cab, out):
            marker.touch()
            _extract_nested_cabs(out, depth - 1)


def _parse_cix_xml(path: Path) -> list[CixEntry]:
    """Parse a PSFX Container Index XML file for PA30 source/target SHA256 pairs.

    Structure (from real Windows Update packages, xmlns="urn:ContainerIndex"):
      <Container>
        <Files>
          <File name="component_path\\afd.sys" ...>
            <Hash alg="SHA256" value="TARGET_HEX"/>   ← patched PE hash
            <Delta>
              <Source type="PA30" name="N">
                <Hash alg="SHA256" value="SOURCE_HEX"/> ← prev PE hash
              </Source>
            </Delta>
          </File>
        </Files>
      </Container>

    Only PA30 delta entries are returned (RAW entries have identical source/target).
    """
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []

    entries: list[CixEntry] = []
    for file_elem in root.iter(f"{{{_NS_CIX}}}File"):
        raw_name = file_elem.get("name", "")
        name = raw_name.replace("\\", "/").split("/")[-1].lower()
        if not _is_kernel_component(name):
            continue

        # Target hash: first <Hash alg="SHA256"> directly under <File>
        target = ""
        hash_elem = file_elem.find(f"{{{_NS_CIX}}}Hash")
        if hash_elem is not None and hash_elem.get("alg", "").upper() == "SHA256":
            target = hash_elem.get("value", "").lower()

        # Source hash: <Delta><Source type="PA30"><Hash alg="SHA256">
        source = ""
        delta_elem = file_elem.find(f"{{{_NS_CIX}}}Delta")
        if delta_elem is not None:
            src_elem = delta_elem.find(f"{{{_NS_CIX}}}Source")
            if src_elem is not None and src_elem.get("type", "").upper() == "PA30":
                src_hash = src_elem.find(f"{{{_NS_CIX}}}Hash")
                if src_hash is not None and src_hash.get("alg", "").upper() == "SHA256":
                    source = src_hash.get("value", "").lower()

        if target and source and source != target:
            entries.append(CixEntry(filename=name, target_sha256=target, source_sha256=source))

    return entries


def _component_name_to_binary(component_name: str) -> Optional[str]:
    """Map a component package name (from assemblyIdentity name= attribute) to a binary filename."""
    lower = component_name.lower()
    for fragment, binary in _COMPONENT_BINARY_MAP:
        if fragment in lower:
            return binary
    return None


def _parse_mum_file(path: Path) -> list[MumEntry]:
    """
    Parse a single .mum manifest and return kernel-component entries.

    Primary path: look for <file> elements with DigestValue (per-component .mum files).
    Fallback: if no <file> elements found, look for <component>/<assemblyIdentity>
    elements in the outer update.mum and map component names to binary filenames.
    """
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []

    identity = root.find(f"{{{_NS_ASM3}}}assemblyIdentity")
    asm_version = identity.get("version", "") if identity is not None else ""

    entries = []
    for file_elem in root.iter(f"{{{_NS_ASM3}}}file"):
        name = file_elem.get("name", "").lower()
        if not _is_kernel_component(name):
            continue
        digest = file_elem.find(f".//{{{_NS_DSIG}}}DigestValue")
        sha256 = ""
        if digest is not None and digest.text:
            try:
                raw = base64.b64decode(digest.text.strip())
                if len(raw) == 32:
                    sha256 = raw.hex()
            except Exception:
                pass
        version = file_elem.get("version", "") or asm_version
        entries.append(MumEntry(filename=name, version=version, sha256=sha256))

    if entries:
        return entries

    # Fallback: outer update.mum has <component> assemblyIdentity but no <file> elements.
    # Map component name → binary filename; SHA256 is not available here.
    for comp_elem in root.iter(f"{{{_NS_ASM3}}}component"):
        comp_id = comp_elem.find(f"{{{_NS_ASM3}}}assemblyIdentity")
        if comp_id is None:
            continue
        comp_name = comp_id.get("name", "")
        comp_version = comp_id.get("version", "")
        binary = _component_name_to_binary(comp_name)
        if binary:
            entries.append(MumEntry(filename=binary, version=comp_version, sha256=""))

    return entries


def extract_delta_mum_entries(package: Path) -> list[MumEntry]:
    """
    Extract a delta MSU/CAB, parse every .mum manifest, and return
    deduplicated kernel-component entries (SHA256-carrying entry wins on conflict).
    """
    seen: dict[str, MumEntry] = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        if not _extract_cab(package, tmp_path):
            return []
        _extract_nested_cabs(tmp_path)
        for mum in tmp_path.rglob("*.mum"):
            for entry in _parse_mum_file(mum):
                prev = seen.get(entry.filename)
                if prev is None or (not prev.sha256 and entry.sha256):
                    seen[entry.filename] = entry
    return list(seen.values())


def _extract_msu_contents(
    package: Path,
    pe_out_dir: Path,
) -> tuple[list[Path], list[MumEntry], list[CixEntry]]:
    """Extract a package once, returning (pe_files, mum_entries, cix_entries).

    pe_files    — kernel-mode x64 PEs found in the cabinet (PA30 deltas skipped).
    mum_entries — kernel-component entries from .mum manifests (for WinBIndex version lookup).
    cix_entries — source/target SHA256 pairs from *.cix.xml (for exact-match lookup).

    All collected in one pass so the large MSU is only unpacked once.
    """
    pe_out_dir.mkdir(parents=True, exist_ok=True)
    collected: dict[str, tuple[Path, Optional[str]]] = {}
    mum_seen: dict[str, MumEntry] = {}
    cix_seen: dict[str, CixEntry] = {}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        if not _extract_cab(package, tmp_path):
            console.print(f"  [red]extraction failed: {package.name}[/red]")
            return [], [], []
        _extract_nested_cabs(tmp_path)

        for f in tmp_path.rglob("*"):
            if not f.is_file():
                continue
            if f.name.lower().endswith(".mum"):
                for entry in _parse_mum_file(f):
                    prev = mum_seen.get(entry.filename)
                    if prev is None or (not prev.sha256 and entry.sha256):
                        mum_seen[entry.filename] = entry
                continue
            # Parse CIX XML files and copy them to pe_out_dir for inspection.
            if f.name.lower().endswith(".cix.xml"):
                shutil.copy2(f, pe_out_dir / f.name)
                for entry in _parse_cix_xml(f):
                    if entry.filename not in cix_seen:
                        cix_seen[entry.filename] = entry
                continue
            if f.suffix.lower() not in BINARY_EXTS:
                continue
            clean = _strip_hash_suffix(f.name)
            if not _is_kernel_component(clean):
                continue
            arch = _path_arch(f)
            if arch in ("arm64", "x86"):
                continue
            prev = collected.get(clean)
            if prev is None or (arch == "x64" and prev[1] != "x64"):
                collected[clean] = (f, arch)

        pe_files: list[Path] = []
        for clean, (src, _) in collected.items():
            if not _is_pe(src):
                # PA30 delta — register for WinBIndex lookup if .mum didn't cover it.
                # CIX target SHA256 (if present) makes this reliable; KB-number is the
                # fallback.  Version is left empty here; _resolve_winbindex_jobs fills it in.
                if clean not in mum_seen:
                    mum_seen[clean] = MumEntry(filename=clean, version="", sha256="")
                continue
            dest = pe_out_dir / clean
            shutil.copy2(src, dest)
            pe_files.append(dest)

    return pe_files, list(mum_seen.values()), list(cix_seen.values())


# --- WinBIndex client ---

def _winbindex_raw(filename: str) -> dict:
    url = f"{WINBINDEX_BASE}/data/by_filename_compressed/{filename.lower()}.json.gz"
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as c:
            r = c.get(url, headers={"User-Agent": "patchpair/1.0", "Accept": "*/*"})
            if r.status_code == 404:
                return {}
            r.raise_for_status()
            return json.loads(gzip.decompress(r.content))
    except Exception as e:
        console.print(f"  [yellow]winbindex error ({filename}): {e}[/yellow]")
        return {}


def _symserver_urls(filename: str, fi: dict, hash_key: str) -> list[str]:
    """Build candidate symbol server URLs for a WinBIndex fileInfo entry.

    Primary: {timestamp:08X}{virtualSize:x} — the standard PE symbol server path.
    Fallback when virtualSize is absent: iterate page-aligned SizeOfImage values in
    the range [max(lastSectionVA + lastSectionRawPtr, size), size + 2MB] and try each.
    This mirrors the WinBIndex site's own download logic for entries without virtualSize.
    """
    urls: list[str] = []
    ts = _parse_int(fi.get("timestamp"))
    vs = _parse_int(fi.get("virtualSize"))

    if ts is not None and vs is not None:
        urls.append(f"{MSDL_BASE}/{filename}/{ts:08X}{vs:x}/{filename}")
    elif ts is not None:
        # virtualSize missing: try a range of page-aligned SizeOfImage candidates.
        size = _parse_int(fi.get("size"))
        last_ptr = _parse_int(fi.get("lastSectionPointerToRawData"))
        last_va = _parse_int(fi.get("lastSectionVirtualAddress"))
        if size and last_ptr is not None and last_va is not None:
            start = max(last_va + last_ptr, size)
            end = size + 2 * 1024 * 1024
            for soi in range(start, end + 1, 0x1000):
                urls.append(f"{MSDL_BASE}/{filename}/{ts:08X}{soi:x}/{filename}")

    if hash_key:
        urls.append(f"{MSDL_BASE}/{filename}/{hash_key}/{filename}")

    # Deduplicate while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _walk_kbs(node) -> list[str]:
    kbs: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if re.match(r"^KB\d{6,8}$", str(k), re.IGNORECASE):
                kbs.append(str(k).upper())
            kbs.extend(_walk_kbs(v))
    elif isinstance(node, list):
        for item in node:
            kbs.extend(_walk_kbs(item))
    return kbs


def _walk_dates(node) -> list[datetime]:
    DATE_KEYS = {"releasedate", "release_date", "date", "initialreleasedate", "builddate"}
    dates: list[datetime] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() in DATE_KEYS:
                dt = _parse_dt(v)
                if dt:
                    dates.append(dt)
            dates.extend(_walk_dates(v))
    elif isinstance(node, list):
        for item in node:
            dates.extend(_walk_dates(item))
    return dates


def _walk_win_versions(node) -> set[str]:
    """Collect Windows version strings like '10-1809', '11-22H2'."""
    found: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if _WIN_VER_KEY_RE.match(str(k)) and not str(k).upper().startswith("KB"):
                found.add(str(k))
            found.update(_walk_win_versions(v))
    elif isinstance(node, list):
        for item in node:
            found.update(_walk_win_versions(item))
    return found


def list_versions(filename: str) -> list[BinVersion]:
    """Return all known versions of filename from WinBIndex, newest first."""
    data = _winbindex_raw(filename)
    versions: list[BinVersion] = []

    for hash_key, entry in data.items():
        if not isinstance(entry, dict):
            continue
        fi = entry.get("fileInfo", {})
        if not fi:
            continue

        urls = _symserver_urls(filename, fi, hash_key)

        wv = entry.get("windowsVersions", {})
        dates = _walk_dates(wv)
        if not dates:
            dt = _parse_dt(fi.get("timestamp"))
            if dt:
                dates = [dt]

        versions.append(BinVersion(
            filename=filename,
            version=fi.get("version", ""),
            sha256=fi.get("sha256", hash_key),
            urls=list(dict.fromkeys(urls)),
            release_date=min(dates) if dates else None,
            kb_numbers=list(dict.fromkeys(_walk_kbs(wv))),
            win_versions=_walk_win_versions(wv),
        ))

    versions.sort(
        key=lambda v: (_dt_key(v.release_date), _parse_version(v.version)),
        reverse=True,
    )
    return versions


def find_by_sha256(filename: str, sha256: str) -> Optional[BinVersion]:
    """Return the WinBIndex entry whose SHA256 matches exactly, or None."""
    return next(
        (v for v in list_versions(filename) if v.sha256.lower() == sha256.lower()),
        None,
    )


def find_prev(
    filename: str,
    patched_version: str,
    patched_sha256: str,
    patched_win_versions: set[str],
) -> Optional[tuple[BinVersion, int]]:
    """
    Find the closest prior version using a three-tier strategy.
    Returns (BinVersion, tier) where tier is 1, 2, or 3, or None if not found.
      1 — same Windows version string (e.g. both from '10-1809')
      2 — same version branch (major.minor.build)
      3 — any strictly older distinct version
    """
    versions = list_versions(filename)
    if not versions:
        return None

    patched_tuple = _parse_version(patched_version)
    branch = patched_tuple[:3]

    candidates = [
        v for v in versions
        if v.sha256 != patched_sha256 and _parse_version(v.version) < patched_tuple
    ]
    if not candidates:
        return None

    # Tier 1: overlapping Windows version
    if patched_win_versions:
        for v in candidates:
            if patched_win_versions & v.win_versions:
                return v, 1

    # Tier 2: same version branch
    branch_matches = [v for v in candidates if _parse_version(v.version)[:3] == branch]
    if branch_matches:
        return branch_matches[0], 2

    return candidates[0], 3


def _vt_download(sha256: str, dest: Path, valid) -> bool:
    """Download a file from VirusTotal by SHA256. Requires VT_API_KEY in the env.

    Used as a fallback when the symbol server no longer hosts an (often old RTM)
    binary. Returns True only if the download succeeds and passes `valid`.
    """
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key or not _SHA256_RE.match(sha256.lower()):
        return False
    url = f"{VT_FILE_API}/{sha256.lower()}/download"
    tmp = dest.with_suffix(dest.suffix + ".vt.part")
    try:
        with httpx.Client(timeout=300.0, follow_redirects=True) as c:
            with c.stream("GET", url, headers={"x-apikey": api_key}) as r:
                if r.status_code != 200:
                    return False
                with open(tmp, "wb") as f:
                    for chunk in r.iter_bytes(8192):
                        f.write(chunk)
    except Exception:
        tmp.unlink(missing_ok=True)
        return False
    if not valid(tmp):
        tmp.unlink(missing_ok=True)
        return False
    tmp.replace(dest)
    return True


def download_binary(bv: BinVersion, dest: Path) -> bool:
    """Download from symbol server to dest. Returns True on success.

    Validates the result: SHA256 check if WinBIndex has one, MZ magic otherwise.
    Rejects PA30 delta files that the symbol server occasionally returns.
    Falls back to VirusTotal (by SHA256) when VT_API_KEY is set and the symbol
    server can't provide the binary.
    """
    expected_sha256 = bv.sha256.lower() if _SHA256_RE.match(bv.sha256.lower()) else None

    def _valid(path: Path) -> bool:
        if expected_sha256:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest() == expected_sha256
        return _is_pe(path)

    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        if _valid(dest):
            return True
        dest.unlink()
    tmp = dest.with_suffix(dest.suffix + ".part")
    statuses: list[int] = []     # HEAD status per candidate URL
    bad_validation = False       # got 200 but content was wrong (PA30 / hash mismatch)
    net_error = ""               # last transport-level exception
    for url in bv.urls:
        try:
            with httpx.Client(timeout=120.0, follow_redirects=True) as c:
                head = c.head(url, headers=HTTP_HEADERS).status_code
                statuses.append(head)
                if head != 200:
                    continue
                with c.stream("GET", url, headers=HTTP_HEADERS) as r:
                    if r.status_code != 200:
                        statuses.append(r.status_code)
                        continue
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_bytes(8192):
                            f.write(chunk)
            if not _valid(tmp):
                bad_validation = True
                tmp.unlink(missing_ok=True)
                continue
            tmp.replace(dest)
            return True
        except Exception as e:
            net_error = f"{type(e).__name__}: {e}"
            tmp.unlink(missing_ok=True)

    # Symbol server exhausted — try VirusTotal by SHA256 (needs VT_API_KEY).
    if expected_sha256 and _vt_download(expected_sha256, dest, _valid):
        console.print(f"    [dim]recovered from VirusTotal: {bv.filename} v{bv.version}[/dim]")
        return True

    # Build a concise failure reason for the caller to surface.
    if net_error:
        bv.last_error = f"network error ({net_error})"
    elif bad_validation:
        bv.last_error = "got 200 but content failed validation (PA30 delta or hash mismatch)"
    elif statuses and all(s == 404 for s in statuses):
        hint = "" if os.environ.get("VT_API_KEY", "").strip() else " (set VT_API_KEY for VirusTotal fallback)"
        bv.last_error = f"404 — not hosted on symbol server (no matching timestamp/size){hint}"
    elif statuses:
        bv.last_error = f"HTTP {sorted(set(statuses))} from symbol server"
    else:
        bv.last_error = "no candidate URLs"
    return False


# --- Pairing / orchestration ---

def _resolve_kb_only_jobs(kb: str, candidates: list[str]) -> list[PatchedJob]:
    """Resolve patched binaries directly from WinBIndex by KB number association.

    Used when the Microsoft Update Catalog has no results for a KB (old KBs are
    eventually removed from the catalog but remain indexed in WinBIndex).
    Resolution only — no download happens here.
    """
    jobs: list[PatchedJob] = []
    for filename in candidates:
        all_v = list_versions(filename)
        bv = next((v for v in all_v if kb in v.kb_numbers), None)
        if bv is None:
            continue
        jobs.append(PatchedJob(clean=filename, bv=bv))
    return jobs


def _resolve_winbindex_jobs(
    kb: str,
    mum_entries: list[MumEntry],
    cix_entries: Optional[list[CixEntry]] = None,
) -> list[PatchedJob]:
    """For each .mum entry locate the patched binary version on WinBIndex.

    Resolution only — no download happens here.  Lookup order:
      1. CIX target SHA256 (exact hash from PSFX index — most reliable)
      2. Version string from .mum manifest
      3. KB number association on WinBIndex
      4. .mum DigestValue SHA256 (only reliable for non-delta packages)
    """
    cix_map = {e.filename: e for e in (cix_entries or [])}
    jobs: list[PatchedJob] = []

    for entry in mum_entries:
        all_v = list_versions(entry.filename)
        bv: Optional[BinVersion] = None

        cix = cix_map.get(entry.filename)
        if cix and cix.target_sha256:
            bv = next((v for v in all_v if v.sha256.lower() == cix.target_sha256), None)

        if bv is None and entry.version:
            bv = next((v for v in all_v if v.version == entry.version), None)

        if bv is None:
            bv = next((v for v in all_v if kb in v.kb_numbers), None)

        if bv is None and entry.sha256:
            bv = next((v for v in all_v if v.sha256.lower() == entry.sha256.lower()), None)

        if bv is None:
            console.print(f"    [yellow]{entry.filename}: not in WinBIndex for this KB[/yellow]")
            continue

        jobs.append(PatchedJob(clean=entry.filename, bv=bv))

    return jobs


def _try_delta_path(kb: str, work_dir: Path, keep: bool = False) -> Optional[list[PatchedJob]]:
    """Download the small delta MSU, parse its .mum manifests for version info,
    then resolve each binary on WinBIndex.  Returns None if no delta exists or
    .mum yields no kernel components (signals process_kb to try the full MSU).
    Resolution only — binaries are downloaded later, one pair at a time."""
    delta_entries = catalog_search_delta(kb)
    if not delta_entries:
        return None

    pkg_dir = work_dir / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    def _download_one_delta(entry: dict) -> Optional[Path]:
        existing = [
            p for p in pkg_dir.glob(f"*{kb}*")
            if "delta" in p.name.lower() and p.suffix.lower() in (".msu", ".cab")
        ]
        if existing:
            console.print(f"  [dim]cached delta: {existing[0].name}[/dim]")
            return existing[0]
        url = _catalog_download_url(entry["update_id"])
        if not url:
            return None
        filename = url.split("/")[-1].split("?")[0]
        if not filename.lower().endswith((".msu", ".cab")):
            filename = f"{kb}_{entry['update_id'][:8]}_delta.msu"
        out = pkg_dir / filename
        tmp = out.with_suffix(".part")
        console.print(f"  downloading delta {filename}...")
        try:
            with httpx.Client(timeout=600.0, follow_redirects=True) as c:
                with c.stream("GET", url, headers=HTTP_HEADERS) as r:
                    r.raise_for_status()
                    total = int(r.headers.get("content-length", 0))
                    with Progress(
                        TextColumn("  [cyan]{task.fields[fn]}"),
                        BarColumn(bar_width=40),
                        "[progress.percentage]{task.percentage:>3.0f}%",
                        DownloadColumn(),
                        TimeRemainingColumn(),
                        console=console,
                    ) as prog:
                        task = prog.add_task("dl", fn=filename, total=total or None)
                        with open(tmp, "wb") as f:
                            for chunk in r.iter_bytes(8192):
                                f.write(chunk)
                                prog.update(task, advance=len(chunk))
            tmp.replace(out)
            return out
        except Exception as e:
            tmp.unlink(missing_ok=True)
            console.print(f"  [red]delta download error: {e}[/red]")
            return None

    mum_entries: list[MumEntry] = []
    for entry in delta_entries:
        delta_pkg = _download_one_delta(entry)
        if not delta_pkg:
            continue
        console.print("  parsing .mum manifests...")
        mum_entries = extract_delta_mum_entries(delta_pkg)
        if not keep:
            delta_pkg.unlink(missing_ok=True)
        if mum_entries:
            break
        console.print(f"  [dim]no kernel components in this delta entry, trying next…[/dim]")

    if not mum_entries:
        console.print("  [yellow]no kernel components in delta .mum — trying full MSU[/yellow]")
        return None

    console.print(f"  .mum entries: {[e.filename for e in mum_entries]}")
    jobs = _resolve_winbindex_jobs(kb, mum_entries)
    return jobs or None


def _make_pair(
    job: PatchedJob,
    kb_meta: KBMeta,
    work_dir: Path,
    output_dir: Path,
    cix_map: dict[str, CixEntry],
) -> Optional[Path]:
    """Materialize one patched binary, find+download its prev, write the pair folder.

    Returns the pair directory on success, None if the patched binary could not be
    obtained.  Each call is self-contained so the pair is written immediately and an
    interrupt loses at most this one binary.
    """
    kb = kb_meta.kb
    clean = job.clean

    # Materialize the patched binary.
    if job.path is not None:
        patched_src = job.path  # already extracted from the MSU cabinet
    else:
        bv = job.bv
        # Resume cheaply: if WinBIndex already gives us the patched SHA256 and the
        # corresponding pair folder exists, skip the download entirely.
        if _SHA256_RE.match(bv.sha256.lower()):
            done = output_dir / f"{Path(clean).stem}_{bv.sha256.lower()[:8]}"
            if (done / "metadata.json").exists():
                console.print(f"  [dim]already done: {done.name}[/dim]")
                return done
        staging = work_dir / "patched_bins" / kb / clean
        console.print(f"  downloading {clean} v{bv.version}...")
        if not download_binary(bv, staging):
            console.print(f"    [yellow]{clean}: patched download failed — {bv.last_error}[/yellow]")
            return None
        patched_src = staging

    sha256  = _sha256(patched_src)
    # pefile first; fall back to the WinBIndex-supplied version when available.
    version = _pe_version(patched_src) or (job.bv.version if job.bv else "") or ""
    pair_dir = output_dir / f"{Path(clean).stem}_{sha256[:8]}"

    if (pair_dir / "metadata.json").exists():
        console.print(f"  [dim]already done: {pair_dir.name}[/dim]")
        return pair_dir

    console.print(f"  [cyan]{clean}[/cyan]  v{version or '?'}")

    # Windows versions this patched binary shipped in, for tier-1 prev matching.
    patched_win_versions: set[str] = job.bv.win_versions if job.bv else set()
    if not patched_win_versions and version:
        match = next((v for v in list_versions(clean) if v.sha256 == sha256), None)
        if match:
            patched_win_versions = match.win_versions

    prev_bv: Optional[BinVersion] = None
    prev_tier: Optional[int] = None

    # CIX source SHA256 identifies the exact base binary the PA30 delta was applied to.
    cix = cix_map.get(clean)
    if cix and cix.source_sha256:
        prev_bv = find_by_sha256(clean, cix.source_sha256)
        if prev_bv:
            prev_tier = 0
            console.print(f"    prev: v{prev_bv.version}  (CIX exact source match)")

    if prev_bv is None:
        if version:
            result = find_prev(clean, version, sha256, patched_win_versions)
            if result:
                prev_bv, prev_tier = result
        else:
            # No version available at all — pick the most recent distinct entry
            prev_bv = next((v for v in list_versions(clean) if v.sha256 != sha256), None)
            prev_tier = 3 if prev_bv else None

    if prev_bv and prev_tier != 0:
        tier_desc = _TIER_DESCRIPTIONS.get(prev_tier, "")
        console.print(f"    prev: v{prev_bv.version}  (tier {prev_tier} — {tier_desc})")
    elif prev_bv is None:
        console.print(f"    [yellow]no previous version found[/yellow]")

    pair_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(clean).stem
    ext  = Path(clean).suffix

    # Stage the prev download first; the final _patched/_unpatched names are
    # assigned by actual PE build version below, so the labels can never be
    # inverted regardless of how the prev binary was selected.
    prev_src: Optional[Path] = None
    if prev_bv:
        prev_src = work_dir / "prev_bins" / kb / clean
        console.print(f"    downloading prev v{prev_bv.version}...")
        if not download_binary(prev_bv, prev_src):
            console.print(f"    [red]prev download failed — {prev_bv.last_error}[/red]")
            prev_src = None

    # Ground-truth versions read straight from the PE files. The patched (fixed)
    # binary is by definition the higher build; if prev-selection handed us a build
    # newer than the KB binary, swap the labels so _patched is always the newer one.
    patched_ver = _pe_version(patched_src) or version
    prev_ver = (_pe_version(prev_src) if prev_src else "") or (prev_bv.version if prev_bv else "")
    naming_corrected = False
    if prev_src and patched_ver and prev_ver \
            and _parse_version(prev_ver) > _parse_version(patched_ver):
        naming_corrected = True
        console.print(
            f"    [yellow]version order inverted: KB binary v{patched_ver} is older than "
            f"prev v{prev_ver} — swapping _patched/_unpatched labels[/yellow]"
        )
        patched_src, prev_src = prev_src, patched_src
        patched_ver, prev_ver = prev_ver, patched_ver

    patched_dest = pair_dir / f"{stem}_patched{ext}"
    shutil.copy2(patched_src, patched_dest)
    patched_sha = _sha256(patched_src)

    prev_dest: Optional[Path] = None
    prev_sha = ""
    if prev_src:
        prev_dest = pair_dir / f"{stem}_unpatched{ext}"
        shutil.copy2(prev_src, prev_dest)
        prev_sha = _sha256(prev_src)

    # Attribute CVEs to this specific binary via title keywords (best-effort).
    # relevant_cves is the attributed subset; cves keeps the full KB list.
    relevant = _cves_for_binary(clean, kb_meta.cves)
    if relevant:
        attribution = "title component match"
        console.print(f"    CVEs for {clean}: {[c.cve_id for c in relevant]}")
    else:
        attribution = "none (no component match — see cves for full KB list)"

    meta: dict = {
        "binary": clean,
        "kb": kb,
        "release_date": kb_meta.release_date,
        "relevant_cves": [_cve_to_dict(c) for c in relevant],
        "cve_attribution": attribution,
        "cves": [_cve_to_dict(c) for c in kb_meta.cves],
        # True when the _patched/_unpatched labels were assigned by PE build version
        # because the KB binary was older than the selected prev (see naming logic).
        "naming_corrected": naming_corrected,
        "patched": {
            "version": patched_ver,
            "sha256": patched_sha,
            "file": f"{stem}_patched{ext}",
        },
        "prev": (
            {
                "version": prev_ver,
                "sha256": prev_sha or prev_bv.sha256,
                "kb_numbers": prev_bv.kb_numbers,
                "win_versions": sorted(prev_bv.win_versions),
                "file": f"{stem}_unpatched{ext}" if prev_dest else None,
                "selection_tier": prev_tier,
                "selection_tier_description": (
                    "CIX exact source match" if prev_tier == 0
                    else _TIER_DESCRIPTIONS.get(prev_tier, "")
                ),
            }
            if prev_bv else None
        ),
    }
    (pair_dir / "metadata.json").write_text(json.dumps(meta, indent=2, default=str))
    console.print(f"    [green]→ {pair_dir}[/green]")
    return pair_dir


def process_kb(kb_meta: KBMeta, work_dir: Path, output_dir: Path, keep: bool = False) -> list[Path]:
    """
    Resolve the KB's kernel binaries (delta path first, full-MSU fallback) into jobs,
    then process each job to completion — downloading the patched binary, finding and
    downloading its prev, and writing the pair folder — before moving to the next.
    Returns list of created pair directory paths.
    """
    kb = kb_meta.kb
    cve_ids = [c.cve_id for c in kb_meta.cves]
    preview = ", ".join(cve_ids[:3]) + ("…" if len(cve_ids) > 3 else "")
    console.print(f"\n[bold cyan]{kb}[/bold cyan]  {kb_meta.release_date or ''}  [{preview or 'manual'}]")

    # Resolve patched binaries into jobs (cheap; no large downloads yet).
    jobs: Optional[list[PatchedJob]] = _try_delta_path(kb, work_dir, keep=keep)
    cix_entries: list[CixEntry] = []

    if jobs is None:
        # No delta MSU — download the full MSU, extract in one pass to get both
        # cabinet PEs (authoritative, works for old KBs) and .mum version strings
        # (fallback to WinBIndex for modern KBs whose cabinets contain only PA30).
        console.print("  [dim]no delta MSU — downloading full MSU[/dim]")
        msu = download_kb_package(kb, work_dir / "packages")
        if not msu:
            # Catalog no longer hosts this KB (common for KBs older than ~3 years).
            # Try WinBIndex directly using KB number association.
            candidates = _cve_candidate_files(kb_meta.cves)
            if candidates:
                console.print(f"  [dim]catalog unavailable — trying WinBIndex for: {candidates}[/dim]")
                jobs = _resolve_kb_only_jobs(kb, candidates)
            if not jobs:
                console.print("  [red]skip — could not download[/red]")
                return []
        else:
            ext_dir = work_dir / "extracted" / kb
            console.print("  extracting full MSU...")
            cabinet_pes, mum_entries, cix_entries = _extract_msu_contents(msu, ext_dir)
            if not keep:
                msu.unlink(missing_ok=True)

            if cix_entries:
                console.print(f"  [dim]CIX entries: {[e.filename for e in cix_entries]}[/dim]")

            if cabinet_pes:
                # Old-style KB: cabinet contains actual PEs.
                jobs = [PatchedJob(clean=p.name.lower(), path=p) for p in cabinet_pes]
            elif mum_entries:
                # Modern KB: cabinet had only PA30 — resolve via WinBIndex.
                console.print("  [dim]cabinet has no PEs (PA30 only) — trying WinBIndex[/dim]")
                console.print(f"  .mum entries: {[e.filename for e in mum_entries]}")
                jobs = _resolve_winbindex_jobs(kb, mum_entries, cix_entries=cix_entries)

        if not jobs:
            console.print("  [yellow]no valid binaries found for this KB[/yellow]")
            return []

    cix_map = {e.filename: e for e in cix_entries}
    console.print(f"  resolved {len(jobs)} binaries: {[j.clean for j in jobs]}")

    created: list[Path] = []
    for job in jobs:
        try:
            pair = _make_pair(job, kb_meta, work_dir, output_dir, cix_map)
        except Exception as e:
            console.print(f"    [red]{job.clean}: error — {e}[/red]")
            continue
        if pair:
            created.append(pair)

    if not keep:
        shutil.rmtree(work_dir / "patched_bins" / kb, ignore_errors=True)
        shutil.rmtree(work_dir / "prev_bins" / kb, ignore_errors=True)
        shutil.rmtree(work_dir / "extracted" / kb, ignore_errors=True)
    return created


def run(
    year_from: int,
    year_to: int,
    output_dir: Path,
    work_dir: Path,
    dry_run: bool = False,
    kb_override: Optional[str] = None,
    cve_override: Optional[str] = None,
    bulletin_override: Optional[str] = None,
    keep: bool = False,
) -> None:
    _print_banner()
    output_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    if kb_override:
        meta = KBMeta(kb=_normalize_kb(kb_override), release_date=None)
        if not dry_run:
            process_kb(meta, work_dir, output_dir, keep=keep)
        return

    if bulletin_override:
        console.print(f"[bold]Looking up KBs for {bulletin_override}...[/bold]")
        kb_map = msrc_bulletin_kbs(bulletin_override)
        if not kb_map:
            console.print(f"[red]No KBs found for {bulletin_override}[/red]")
            return
        console.print(f"  {len(kb_map)} KB(s): {', '.join(kb_map)}")
        if dry_run:
            t = Table(title=f"{bulletin_override} — KBs (dry run)")
            t.add_column("KB", style="cyan")
            t.add_column("Date")
            t.add_column("CVEs")
            for meta in kb_map.values():
                cve_ids = [c.cve_id for c in meta.cves]
                t.add_row(meta.kb, meta.release_date or "", ", ".join(cve_ids))
            console.print(t)
            return
        for meta in kb_map.values():
            year_dir = output_dir / (meta.release_date[:4] if meta.release_date else "unknown")
            try:
                process_kb(meta, work_dir, year_dir, keep=keep)
            except Exception as e:
                console.print(f"[red]error processing {meta.kb}: {e}[/red]")
        return

    if cve_override:
        console.print(f"[bold]Looking up KBs for {cve_override}...[/bold]")
        kb_map = msrc_cve_kbs(cve_override)
        if not kb_map:
            console.print(f"[red]No KBs found for {cve_override}[/red]")
            return
        console.print(f"  {len(kb_map)} KB(s): {', '.join(kb_map)}")
        if dry_run:
            t = Table(title=f"{cve_override} — KBs (dry run)")
            t.add_column("KB", style="cyan")
            t.add_column("Date")
            t.add_column("CVEs")
            for meta in kb_map.values():
                cve_ids = [c.cve_id for c in meta.cves]
                t.add_row(meta.kb, meta.release_date or "", ", ".join(cve_ids))
            console.print(t)
            return
        for meta in kb_map.values():
            year_dir = output_dir / (meta.release_date[:4] if meta.release_date else "unknown")
            try:
                process_kb(meta, work_dir, year_dir, keep=keep)
            except Exception as e:
                console.print(f"[red]error processing {meta.kb}: {e}[/red]")
        return

    console.print(f"[bold]Querying MSRC for {year_from}–{year_to}...[/bold]")
    update_ids = msrc_update_ids(year_from, year_to)
    console.print(f"  {len(update_ids)} monthly advisory documents")

    all_kbs: dict[str, KBMeta] = {}
    for uid, _ in update_ids:
        console.print(f"  [dim]{uid}[/dim] ", end="")
        try:
            kb_map = msrc_kernel_kbs(uid)
            for kb, meta in kb_map.items():
                if kb not in all_kbs:
                    all_kbs[kb] = meta
                else:
                    known = {c.cve_id for c in all_kbs[kb].cves}
                    for cve in meta.cves:
                        if cve.cve_id not in known:
                            all_kbs[kb].cves.append(cve)
            console.print(f"→ {len(kb_map)} kernel KBs")
        except Exception as e:
            console.print(f"[red]error: {e}[/red]")
        time.sleep(0.5)

    console.print(f"\n[bold]Unique KBs with kernel CVEs: {len(all_kbs)}[/bold]")

    if dry_run:
        t = Table(title="Kernel-component KBs (dry run — nothing downloaded)")
        t.add_column("KB", style="cyan")
        t.add_column("Date")
        t.add_column("CVE count", justify="right")
        t.add_column("CVEs")
        for meta in sorted(all_kbs.values(), key=lambda m: m.release_date or ""):
            cve_ids = [c.cve_id for c in meta.cves]
            t.add_row(
                meta.kb,
                meta.release_date or "",
                str(len(cve_ids)),
                ", ".join(cve_ids[:4]) + ("…" if len(cve_ids) > 4 else ""),
            )
        console.print(t)
        return

    for meta in sorted(all_kbs.values(), key=lambda m: m.release_date or ""):
        year_dir = output_dir / (meta.release_date[:4] if meta.release_date else "unknown")
        try:
            process_kb(meta, work_dir, year_dir, keep=keep)
        except Exception as e:
            console.print(f"[red]error processing {meta.kb}: {e}[/red]")
        time.sleep(1)


# --- CLI ---

def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--year", type=int, metavar="YYYY", help="Single year (e.g. 2024)")
    grp.add_argument("--year-from", type=int, metavar="YYYY", dest="year_from", help="Start of year range")
    p.add_argument("--year-to", type=int, metavar="YYYY", dest="year_to", help="End of year range (inclusive, default: current year)")
    p.add_argument("--kb", metavar="KBXXXXXXX", help="Process a single KB directly (skips MSRC lookup)")
    p.add_argument("--cve", metavar="CVE-YYYY-NNNNN", help="Process a single CVE: fetch its KB(s) from MSRC and download the patched binaries")
    p.add_argument("--ms", metavar="MSYY-NNN", dest="ms_bulletin", help="Process an MS Security Bulletin (e.g. MS16-014): scrape its CVEs then fetch the KB(s)")
    p.add_argument("--output", default="./pairs", metavar="DIR", help="Where to write pair folders (default: ./pairs)")
    p.add_argument("--work-dir", default="./work", metavar="DIR", dest="work_dir", help="Scratch space for downloads and extraction (default: ./work)")
    p.add_argument("--dry-run", action="store_true", help="List matching KBs and CVEs without downloading anything")
    p.add_argument("--keep", action="store_true", help="Keep work/extracted files after processing (for inspection)")

    args = p.parse_args()

    if not args.kb and not args.cve and not args.ms_bulletin:
        if args.year:
            year_from = year_to = args.year
        elif args.year_from:
            year_from = args.year_from
            year_to = args.year_to or datetime.now().year
        else:
            p.error("provide --year, --year-from [--year-to], --kb, --cve, or --ms")
            return
    else:
        year_from = year_to = datetime.now().year  # unused for --kb / --cve / --ms mode

    run(
        year_from=year_from,
        year_to=year_to,
        output_dir=Path(args.output),
        work_dir=Path(args.work_dir),
        dry_run=args.dry_run,
        kb_override=args.kb,
        cve_override=args.cve,
        bulletin_override=args.ms_bulletin,
        keep=args.keep,
    )


if __name__ == "__main__":
    main()
