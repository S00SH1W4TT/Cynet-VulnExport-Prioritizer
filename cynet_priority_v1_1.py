#!/usr/bin/env python3
"""cynet_priority.py

Purpose
  Take a Cynet/Cybet vulnerability export (XLSX/CSV) and produce a client-ready XLSX
  with:
    - Exposure classification (Server/AVD/Workstation) from scan_group
    - P0–P3 priority (offline rules)
    - SLA days + Target remediation date (based on last_seen/first_seen)
    - Recommended action (uses cve_version_end when present)

Convenience output
  - Writes a small CVE list file alongside the output (or to --cves-out) so you can
    quickly enrich using a single internet-connected machine later.

Optional enrichment (recommended for higher accuracy)
  - KEV: mark CVEs that appear in CISA Known Exploited Vulnerabilities catalog (local file)
  - EPSS: add EPSS probability (either via FIRST API, or from a local EPSS CSV)

Notes
  - This script intentionally does NOT require a "Patch Available" column.
  - Column names are normalized to lowercase with underscores.

Additions (Grouping / Noise reduction)
  - Adds 2 summary sheets:
      * Grouped_by_CVE: one row per CVE with hosts/products rolled up into single cells
      * Grouped_by_CVE_Product: one row per (CVE + software_family) to reduce Office/Adobe spam
"""

import argparse
import gzip
import io
import json
import re
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

import pandas as pd

try:
    import requests  # optional; only needed for --epss-api
except Exception:
    requests = None

EPSS_API = "https://api.first.org/data/v1/epss"

# Ordering helpers for rollups
SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
P_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def norm_col(c: str) -> str:
    c = str(c).strip().lower()
    c = re.sub(r"\s+", "_", c)
    c = c.replace("-", "_")
    return c


def normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [norm_col(c) for c in df.columns]
    return df


def exposure_from_group(scan_group: str) -> str:
    s = str(scan_group).lower()
    if "server" in s or "servers" in s:
        return "Server"
    if "avd" in s:
        return "AVD"
    if "workstation" in s or "workstations" in s:
        return "Workstation"
    return "Unknown"


def sla_days(severity: str) -> int:
    # Critical 72 hours (~3 days), High 7 days, Medium/Low 30 days.
    s = str(severity).strip().upper()
    if s == "CRITICAL":
        return 3
    if s == "HIGH":
        return 7
    return 30


def priority_p0_p3(severity: str, exposure: str, kev: bool = False, epss: Optional[float] = None) -> str:
    s = str(severity).strip().upper()

    # Strong exploitation signals
    if kev:
        return "P0"
    if epss is not None and epss >= 0.80:
        return "P0"

    # Baseline severity
    if s == "CRITICAL":
        return "P0"
    if s == "HIGH":
        return "P1"
    if s == "MEDIUM":
        return "P2"
    return "P3"


def looks_like_version(val) -> bool:
    if val is None:
        return False
    if pd.isna(val):
        return False
    s = str(val).strip()
    if not s or s.lower() in {"nan", "none", "null"}:
        return False
    if s.startswith("{") and s.endswith("}"):
        return False
    return any(ch.isdigit() for ch in s)


def recommended_action(software_name: str, cve_version_end) -> str:
    sw = (software_name or "").strip()
    if looks_like_version(cve_version_end):
        return f"Update {sw} to {str(cve_version_end).strip()} or later (per finding fix version)."
    return f"Update {sw} to the latest vendor-supported version and re-scan to confirm."


def load_input(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        df = pd.read_csv(path)
    else:
        df = pd.read_excel(path, engine="openpyxl")
    return normalize_df(df)


def parse_dates(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ("first_seen", "last_seen"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
    return df


def load_kev(kev_path: Path) -> Set[str]:
    """Load KEV CVE IDs from CISA KEV CSV or JSON."""
    if kev_path.suffix.lower() == ".csv":
        kev_df = pd.read_csv(kev_path)
        kev_df.columns = [norm_col(c) for c in kev_df.columns]
        cve_col = "cveid" if "cveid" in kev_df.columns else ("cve_id" if "cve_id" in kev_df.columns else None)
        if not cve_col:
            raise ValueError("Could not find CVE column in KEV CSV")
        return set(kev_df[cve_col].dropna().astype(str))

    data = json.loads(kev_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "vulnerabilities" in data:
        items = data["vulnerabilities"]
    elif isinstance(data, list):
        items = data
    else:
        items = data.get("data", []) if isinstance(data, dict) else []

    cves = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        cve = it.get("cveID") or it.get("cveId") or it.get("cve_id") or it.get("cve")
        if cve:
            cves.add(str(cve))
    return cves


def load_epss_csv(path: Path) -> Dict[str, float]:
    """Load EPSS scores from a CSV or gzipped CSV with columns: cve, epss, percentile"""
    if path.suffix.lower().endswith(".gz"):
        raw = gzip.open(path, "rb").read()
        bio = io.BytesIO(raw)
        epss_df = pd.read_csv(bio, comment="#")
    else:
        epss_df = pd.read_csv(path, comment="#")

    epss_df.columns = [norm_col(c) for c in epss_df.columns]
    if "cve" not in epss_df.columns or "epss" not in epss_df.columns:
        raise ValueError("EPSS CSV must include 'cve' and 'epss' columns")

    out = {}
    for _, r in epss_df.iterrows():
        try:
            out[str(r["cve"]).strip()] = float(r["epss"])
        except Exception:
            pass
    return out


def fetch_epss_api(cves: Iterable[str]) -> Dict[str, float]:
    """Fetch EPSS scores via FIRST API (batching). Requires requests."""
    if requests is None:
        raise RuntimeError("requests not available. Install with: pip install requests")

    cves = [c for c in set(map(str, cves)) if c.startswith("CVE-")]
    out: Dict[str, float] = {}
    batch_size = 80

    for i in range(0, len(cves), batch_size):
        batch = cves[i : i + batch_size]
        resp = requests.get(EPSS_API, params={"cve": ",".join(batch)})
        resp.raise_for_status()
        data = resp.json().get("data", [])
        for row in data:
            try:
                out[str(row.get("cve")).strip()] = float(row.get("epss"))
            except Exception:
                continue
    return out


def build_output(df: pd.DataFrame, kev_set: Optional[Set[str]] = None, epss_map: Optional[Dict[str, float]] = None) -> pd.DataFrame:
    df = df.copy()

    if "scan_group" in df.columns:
        df["exposure"] = df["scan_group"].apply(exposure_from_group)
    else:
        df["exposure"] = "Unknown"

    df["sla_days"] = df["severity"].apply(sla_days) if "severity" in df.columns else 30

    base = None
    if "last_seen" in df.columns:
        base = df["last_seen"]
    elif "first_seen" in df.columns:
        base = df["first_seen"]

    if base is not None:
        df["target_remediation_date"] = base + pd.to_timedelta(df["sla_days"], unit="D")

    if kev_set is not None and "cve_id" in df.columns:
        df["kev"] = df["cve_id"].astype(str).isin(kev_set)
    else:
        df["kev"] = False

    if epss_map is not None and "cve_id" in df.columns:
        df["epss"] = df["cve_id"].astype(str).map(epss_map)
    else:
        df["epss"] = pd.NA

    df["priority"] = df.apply(
        lambda r: priority_p0_p3(
            r.get("severity", ""),
            r.get("exposure", "Unknown"),
            bool(r.get("kev", False)),
            r.get("epss", None) if pd.notna(r.get("epss", pd.NA)) else None,
        ),
        axis=1,
    )

    df["recommended_action"] = df.apply(
        lambda r: recommended_action(r.get("software_name", r.get("software", "")), r.get("cve_version_end", None)),
        axis=1,
    )

    if "cve_id" in df.columns:
        df["nvd_link"] = df["cve_id"].astype(str).apply(
            lambda c: f"https://nvd.nist.gov/vuln/detail/{c}" if c.startswith("CVE-") else ""
        )

    keys = [c for c in ("host_name", "software_name", "cve_id") if c in df.columns]
    if keys:
        df = df.drop_duplicates(subset=keys)

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    df["_p"] = df["priority"].map(order).fillna(9)
    if "score" in df.columns:
        df["score"] = pd.to_numeric(df["score"], errors="coerce")
        df = df.sort_values(by=["_p", "score"], ascending=[True, False])
    else:
        df = df.sort_values(by=["_p"])
    df = df.drop(columns=["_p"])

    preferred = [
        "scan_group", "host_name", "drive_serial",
        "software_name", "software_version",
        "cve_id", "score", "severity",
        "exposure", "kev", "epss", "priority",
        "sla_days", "target_remediation_date",
        "cve_version_end", "reference", "nvd_link",
        "recommended_action", "cve_description",
    ]
    cols = [c for c in preferred if c in df.columns]
    return df[cols]


def write_cve_list(df: pd.DataFrame, out_path: Path):
    if "cve_id" not in df.columns:
        return
    cves = (
        df["cve_id"].dropna().astype(str).str.strip().loc[lambda s: s.str.startswith("CVE-")].unique().tolist()
    )
    cves.sort()
    out_path.write_text("\n".join(cves) + ("\n" if cves else ""), encoding="utf-8")


# -----------------------------
# Grouping / roll-up functions
# -----------------------------

def _as_str_series(s: pd.Series) -> pd.Series:
    return s.fillna("").astype(str).str.strip()


def join_unique(s: pd.Series, sep: str = ", ", limit: int = 30) -> str:
    """
    Join unique values; optionally limit list length to keep Excel cells readable.
    This is what makes hosts comma-separated in ONE cell per group.
    """
    vals = [v for v in _as_str_series(s).tolist() if v and v.lower() not in {"nan", "none", "null"}]
    uniq = []
    seen = set()
    for v in vals:
        if v not in seen:
            uniq.append(v)
            seen.add(v)
    if limit and len(uniq) > limit:
        return sep.join(uniq[:limit]) + f"{sep}(+{len(uniq)-limit} more)"
    return sep.join(uniq)


def mode_or_first(s: pd.Series) -> str:
    """Most common value (mode); fallback to first non-empty."""
    s2 = _as_str_series(s)
    s2 = s2[s2 != ""]
    if s2.empty:
        return ""
    m = s2.mode()
    return str(m.iloc[0]) if not m.empty else str(s2.iloc[0])


def worst_severity(s: pd.Series) -> str:
    s2 = _as_str_series(s).str.upper()
    if s2.empty:
        return ""
    ranked = s2.map(lambda x: SEV_ORDER.get(x, 0))
    max_rank = ranked.max()
    for label, r in SEV_ORDER.items():
        if r == max_rank:
            return label
    return ""


def add_software_family(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize software into a family label (helps collapse Office component spam)."""
    df = df.copy()
    base_col = "software_name" if "software_name" in df.columns else ("software" if "software" in df.columns else None)
    if not base_col:
        df["software_family"] = ""
        return df

    df["software_family"] = (
        df[base_col]
        .fillna("")
        .astype(str)
        .str.replace(r"\(.*?\)", "", regex=True)  # remove parenthetical qualifiers
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )
    return df


def build_grouped_view(
    out_df: pd.DataFrame,
    group_mode: str = "cve",  # "cve" or "cve_product"
    host_list_limit: int = 30,
    product_list_limit: int = 30,
) -> pd.DataFrame:
    """
    Roll up rows into fewer entries.
    - cve: one row per CVE
    - cve_product: one row per (CVE + software_family)
    """
    df = out_df.copy()
    df = add_software_family(df)

    # Decide grouping keys
    keys = ["cve_id"]
    if group_mode == "cve_product":
        keys.append("software_family")

    # Ensure numeric score
    if "score" in df.columns:
        df["score"] = pd.to_numeric(df["score"], errors="coerce")

    g = df.groupby(keys, dropna=False)

    # Priority: keep the most urgent (P0 beats P1 beats P2 beats P3)
    def _best_priority(series: pd.Series) -> str:
        vals = _as_str_series(series)
        if vals.empty:
            return "P3"
        best = min(vals.map(lambda x: P_ORDER.get(str(x), 9)).fillna(9))
        inv = {v: k for k, v in P_ORDER.items()}
        return inv.get(best, "P3")

    grouped = pd.DataFrame({
        "MaxScore": g["score"].max() if "score" in df.columns else pd.NA,
        "Severity": g["severity"].agg(worst_severity) if "severity" in df.columns else "",
        "Priority": g["priority"].agg(_best_priority) if "priority" in df.columns else "P3",
        "Exposure": g["exposure"].agg(mode_or_first) if "exposure" in df.columns else "",
        "KEV": g["kev"].any() if "kev" in df.columns else False,
        "EPSS": g["epss"].max() if "epss" in df.columns else pd.NA,

        # These two are the key noise reducers:
        "AffectedHostsCount": g["host_name"].nunique() if "host_name" in df.columns else pd.NA,
        "AffectedHosts": g["host_name"].agg(lambda s: join_unique(s, limit=host_list_limit)) if "host_name" in df.columns else "",

        # Helpful context: software list / family list
        "AffectedProducts": (
            g["software_name"].agg(lambda s: join_unique(s, limit=product_list_limit))
            if "software_name" in df.columns
            else g["software_family"].agg(lambda s: join_unique(s, limit=product_list_limit))
        ),

        "TargetRemediationDate": g["target_remediation_date"].min() if "target_remediation_date" in df.columns else pd.NaT,
        "RecommendedAction": g["recommended_action"].agg(mode_or_first) if "recommended_action" in df.columns else "",
        "Reference": g["reference"].agg(mode_or_first) if "reference" in df.columns else "",
    }).reset_index()

    # Add NVD link
    if "cve_id" in grouped.columns:
        grouped["nvd_link"] = grouped["cve_id"].astype(str).apply(
            lambda c: f"https://nvd.nist.gov/vuln/detail/{c}" if c.startswith("CVE-") else ""
        )

    # Sort: Priority then score
    grouped["_p"] = grouped["Priority"].map(P_ORDER).fillna(9)
    if "MaxScore" in grouped.columns:
        grouped = grouped.sort_values(by=["_p", "MaxScore"], ascending=[True, False])
    else:
        grouped = grouped.sort_values(by=["_p"])
    grouped = grouped.drop(columns=["_p"])

    # Column order
    preferred = [
        "cve_id",
        "software_family" if group_mode == "cve_product" else None,
        "MaxScore",
        "Severity",
        "Priority",
        "KEV",
        "EPSS",
        "AffectedHostsCount",
        "AffectedHosts",
        "AffectedProducts",
        "TargetRemediationDate",
        "nvd_link",
        "Reference",
        "RecommendedAction",
    ]
    preferred = [c for c in preferred if c and c in grouped.columns]
    rest = [c for c in grouped.columns if c not in preferred]
    return grouped[preferred + rest]


def main():
    ap = argparse.ArgumentParser(description="Prioritize Cynet/Cybet vuln exports into P0–P3 and optionally enrich with KEV/EPSS.")
    ap.add_argument("input", help="Input export (.xlsx or .csv)")
    ap.add_argument("output", help="Output .xlsx")

    # Convenience output
    ap.add_argument("--cves-out", help="Write unique CVEs from input to a text file (default: alongside output)")

    # Enrichment options
    ap.add_argument("--kev", help="Path to CISA KEV CSV or JSON (downloaded locally)")
    ap.add_argument("--epss-csv", help="Path to EPSS CSV or .csv.gz (downloaded locally)")
    ap.add_argument("--epss-api", action="store_true", help="Fetch EPSS via FIRST API (requires internet + requests)")

    # Grouping controls (optional)
    ap.add_argument("--host-list-limit", type=int, default=30, help="Max hosts to list in grouped sheets (default: 30)")
    ap.add_argument("--product-list-limit", type=int, default=30, help="Max products to list in grouped sheets (default: 30)")

    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    df = parse_dates(load_input(in_path))

    kev_set = None
    if args.kev:
        kev_set = load_kev(Path(args.kev))

    epss_map = None
    if args.epss_csv:
        epss_map = load_epss_csv(Path(args.epss_csv))
    elif args.epss_api:
        if "cve_id" not in df.columns:
            raise RuntimeError("Input does not include cve_id; cannot enrich with EPSS")
        epss_map = fetch_epss_api(df["cve_id"].dropna().astype(str).tolist())

    out_df = build_output(df, kev_set=kev_set, epss_map=epss_map)

    # Write CVE list file (default next to output)
    cves_out_path = Path(args.cves_out) if args.cves_out else out_path.with_suffix("").with_name(out_path.stem + "_cves_in_scan.txt")
    write_cve_list(df, cves_out_path)

    # Build grouped views from the prioritized output
    grouped_cve = build_grouped_view(out_df, group_mode="cve", host_list_limit=args.host_list_limit, product_list_limit=args.product_list_limit)
    grouped_cve_prod = build_grouped_view(out_df, group_mode="cve_product", host_list_limit=args.host_list_limit, product_list_limit=args.product_list_limit)

    # Write workbook with multiple sheets
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        out_df.to_excel(writer, index=False, sheet_name="Prioritized")
        grouped_cve.to_excel(writer, index=False, sheet_name="Grouped_by_CVE")
        grouped_cve_prod.to_excel(writer, index=False, sheet_name="Grouped_by_CVE_Product")


if __name__ == "__main__":
    main()