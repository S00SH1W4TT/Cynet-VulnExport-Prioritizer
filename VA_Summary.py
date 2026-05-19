#!/usr/bin/env python3
"""cynet_priority.py

Updated: Removed 'Grouped_by_CVE_Product' sheet and specific columns: 
'exposure', 'sla_days', 'target_remediation_date', 'cve_version'
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
    import requests
except Exception:
    requests = None

EPSS_API = "https://api.first.org/data/v1/epss"

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
    s = str(severity).strip().upper()
    if s == "CRITICAL":
        return 3
    if s == "HIGH":
        return 7
    return 30

def priority_p0_p3(severity: str, exposure: str, kev: bool = False, epss: Optional[float] = None) -> str:
    s = str(severity).strip().upper()
    if kev or (epss is not None and epss >= 0.80):
        return "P0"
    if s == "CRITICAL":
        return "P0"
    if s == "HIGH":
        return "P1"
    if s == "MEDIUM":
        return "P2"
    return "P3"

def looks_like_version(val) -> bool:
    if val is None or pd.isna(val):
        return False
    s = str(val).strip()
    if not s or s.lower() in {"nan", "none", "null"}:
        return False
    return any(ch.isdigit() for ch in s)

def recommended_action(software_name: str, cve_version_end) -> str:
    sw = (software_name or "").strip()
    if looks_like_version(cve_version_end):
        return f"Update {sw} to {str(cve_version_end).strip()} or later."
    return f"Update {sw} to the latest vendor-supported version."

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
    if kev_path.suffix.lower() == ".csv":
        kev_df = pd.read_csv(kev_path)
        kev_df.columns = [norm_col(c) for c in kev_df.columns]
        cve_col = next((c for c in ["cveid", "cve_id"] if c in kev_df.columns), None)
        return set(kev_df[cve_col].dropna().astype(str)) if cve_col else set()
    
    data = json.loads(kev_path.read_text(encoding="utf-8"))
    items = data.get("vulnerabilities", data.get("data", [])) if isinstance(data, dict) else data
    return {str(it.get("cveID") or it.get("cve_id")) for it in items if isinstance(it, dict)}

def load_epss_csv(path: Path) -> Dict[str, float]:
    f = gzip.open(path, "rb") if path.suffix.lower().endswith(".gz") else open(path, "rb")
    epss_df = pd.read_csv(f, comment="#")
    epss_df.columns = [norm_col(c) for c in epss_df.columns]
    return dict(zip(epss_df["cve"].astype(str), epss_df["epss"].astype(float)))

def build_output(df: pd.DataFrame, kev_set: Optional[Set[str]] = None, epss_map: Optional[Dict[str, float]] = None) -> pd.DataFrame:
    df = df.copy()

    # Calculate values for logic, but these will be excluded from final columns if requested
    temp_exposure = df["scan_group"].apply(exposure_from_group) if "scan_group" in df.columns else "Unknown"
    
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
            temp_exposure,
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

    # Sort logic
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    df["_p"] = df["priority"].map(order).fillna(9)
    if "score" in df.columns:
        df["score"] = pd.to_numeric(df["score"], errors="coerce")
        df = df.sort_values(by=["_p", "score"], ascending=[True, False])
    else:
        df = df.sort_values(by=["_p"])
    
    # FINAL COLUMN SELECTION (Removed exposure, sla_days, target_remediation_date, cve_version)
    preferred = [
        "scan_group", "host_name", "drive_serial",
        "software_name", "software_version",
        "cve_id", "score", "severity",
        "kev", "epss", "priority",
        "reference", "nvd_link",
        "recommended_action", "cve_description",
    ]
    cols = [c for c in preferred if c in df.columns]
    return df[cols]

def join_unique(s: pd.Series, limit: int = 30) -> str:
    vals = [str(v) for v in s.dropna().unique() if str(v).lower() not in {"nan", "none", ""}]
    if limit and len(vals) > limit:
        return ", ".join(vals[:limit]) + f", (+{len(vals)-limit} more)"
    return ", ".join(vals)

def build_grouped_view(out_df: pd.DataFrame, host_list_limit: int = 30) -> pd.DataFrame:
    df = out_df.copy()
    if "score" in df.columns:
        df["score"] = pd.to_numeric(df["score"], errors="coerce")

    g = df.groupby("cve_id", dropna=False)

    grouped = pd.DataFrame({
        "MaxScore": g["score"].max() if "score" in df.columns else pd.NA,
        "Severity": g["severity"].first() if "severity" in df.columns else "",
        "Priority": g["priority"].first() if "priority" in df.columns else "P3",
        "KEV": g["kev"].any() if "kev" in df.columns else False,
        "EPSS": g["epss"].max() if "epss" in df.columns else pd.NA,
        "AffectedHostsCount": g["host_name"].nunique() if "host_name" in df.columns else 0,
        "AffectedHosts": g["host_name"].agg(lambda s: join_unique(s, limit=host_list_limit)) if "host_name" in df.columns else "",
        "AffectedProducts": g["software_name"].agg(join_unique) if "software_name" in df.columns else "",
        "RecommendedAction": g["recommended_action"].first() if "recommended_action" in df.columns else "",
    }).reset_index()

    if "cve_id" in grouped.columns:
        grouped["nvd_link"] = grouped["cve_id"].apply(lambda c: f"https://nvd.nist.gov/vuln/detail/{c}" if str(c).startswith("CVE-") else "")

    return grouped

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--kev")
    ap.add_argument("--epss-csv")
    args = ap.parse_args()

    df = parse_dates(load_input(Path(args.input)))
    kev_set = load_kev(Path(args.kev)) if args.kev else None
    epss_map = load_epss_csv(Path(args.epss_csv)) if args.epss_csv else None

    out_df = build_output(df, kev_set=kev_set, epss_map=epss_map)
    grouped_cve = build_grouped_view(out_df)

    with pd.ExcelWriter(args.output, engine="openpyxl") as writer:
        out_df.to_excel(writer, index=False, sheet_name="Prioritized")
        grouped_cve.to_excel(writer, index=False, sheet_name="Grouped_by_CVE")

if __name__ == "__main__":
    main()