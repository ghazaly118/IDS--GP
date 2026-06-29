import re
from pathlib import Path

import numpy as np
import pandas as pd


AMP_PORTS = {53, 123, 161, 389, 500, 1900, 4500, 11211, 37810, 47808, 10001}
BRUTEFORCE_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 5900}


def _clean_col(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _pick_col(df: pd.DataFrame, candidates: list[str]):
    lookup = {_clean_col(c): c for c in df.columns}
    for cand in candidates:
        key = _clean_col(cand)
        if key in lookup:
            return lookup[key]
    return None


def _num_series(df: pd.DataFrame, col_name: str | None, default: float = 0.0):
    if col_name is None or col_name not in df.columns:
        return pd.Series([default] * len(df), index=df.index, dtype="float64")
    return pd.to_numeric(df[col_name], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(default)


def _str_series(df: pd.DataFrame, col_name: str | None, default: str = ""):
    if col_name is None or col_name not in df.columns:
        return pd.Series([default] * len(df), index=df.index, dtype="object")
    return df[col_name].astype(str).fillna(default)


def _add_rule(rule_list, rule_id, severity, title, description, evidence=None):
    rule_list.append({
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence or {}
    })


def analyze_csv_with_rules(csv_path: str):
    csv_path = str(Path(csv_path))
    df = pd.read_csv(csv_path, low_memory=False)

    if df.empty:
        return {
            "summary": {
                "status": "ok",
                "file": Path(csv_path).name,
                "total_flows": 0,
                "triggered_rules": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0,
            },
            "triggered_rules": [],
            "sample_hits": [],
        }

    # --- Column discovery ---
    src_ip_col = _pick_col(df, ["Src IP", "Source IP"])
    dst_ip_col = _pick_col(df, ["Dst IP", "Destination IP"])
    src_port_col = _pick_col(df, ["Src Port", "Source Port"])
    dst_port_col = _pick_col(df, ["Dst Port", "Destination Port"])
    proto_col = _pick_col(df, ["Protocol"])
    flow_packets_s_col = _pick_col(df, ["Flow Packets/s"])
    flow_bytes_s_col = _pick_col(df, ["Flow Bytes/s"])
    flow_duration_col = _pick_col(df, ["Flow Duration", "Flow duration"])
    bwd_pkts_col = _pick_col(df, ["Total Backward Packets", "Total Bwd packets", "Subflow Bwd Packets"])
    fwd_pkts_col = _pick_col(df, ["Total Fwd Packets", "Total Fwd Packet", "Subflow Fwd Packets"])
    pkt_len_mean_col = _pick_col(df, ["Packet Length Mean", "Average Packet Size", "Avg Packet Size"])
    flow_iat_mean_col = _pick_col(df, ["Flow IAT Mean"])

    # --- Numeric series ---
    protocol = _num_series(df, proto_col, 0)
    src_port = _num_series(df, src_port_col, -1).astype(int)
    dst_port = _num_series(df, dst_port_col, -1).astype(int)
    flow_packets_s = _num_series(df, flow_packets_s_col, 0.0)
    flow_bytes_s = _num_series(df, flow_bytes_s_col, 0.0)
    flow_duration = _num_series(df, flow_duration_col, 0.0)
    bwd_pkts = _num_series(df, bwd_pkts_col, 0.0)
    fwd_pkts = _num_series(df, fwd_pkts_col, 0.0)
    pkt_len_mean = _num_series(df, pkt_len_mean_col, 0.0)
    flow_iat_mean = _num_series(df, flow_iat_mean_col, 0.0)

    src_ip = _str_series(df, src_ip_col, "")
    dst_ip = _str_series(df, dst_ip_col, "")

    triggered_rules = []
    sample_hits = []

    total_flows = len(df)

    # =========================================================
    # RULE 1: UDP Amplification / Reflection
    # =========================================================
    udp_mask = protocol == 17
    amp_port_mask = src_port.isin(AMP_PORTS) | dst_port.isin(AMP_PORTS)
    low_back_mask = bwd_pkts <= 1

    amp_mask = udp_mask & amp_port_mask & low_back_mask

    if int(amp_mask.sum()) >= 20:
        _add_rule(
            triggered_rules,
            rule_id="RULE_AMP_UDP_001",
            severity="High",
            title="Possible UDP Amplification / Reflection",
            description="Many UDP flows use known amplification ports with almost no backward packets.",
            evidence={
                "matched_flows": int(amp_mask.sum()),
                "total_flows": total_flows,
                "ratio_percent": round(float(amp_mask.mean()) * 100, 2),
                "common_ports_seen": sorted(list(set(src_port[amp_mask].tolist() + dst_port[amp_mask].tolist()) & AMP_PORTS))[:10]
            }
        )

        amp_sample = df.loc[amp_mask, [c for c in [src_ip_col, dst_ip_col, src_port_col, dst_port_col, proto_col] if c]].head(10)
        sample_hits.extend(amp_sample.to_dict(orient="records"))

    # =========================================================
    # RULE 2: High-rate flood behavior
    # =========================================================
    high_rate_mask = (
        ((flow_packets_s >= 1000) | (flow_bytes_s >= 1_000_000)) &
        (fwd_pkts >= 5) &
        (bwd_pkts <= 1)
    )

    if int(high_rate_mask.sum()) >= 50 and float(high_rate_mask.mean()) >= 0.20:
        _add_rule(
            triggered_rules,
            rule_id="RULE_DOS_FLOOD_001",
            severity="High",
            title="Possible DoS / Flood Traffic",
            description="A large portion of flows show very high flow rate with minimal return traffic.",
            evidence={
                "matched_flows": int(high_rate_mask.sum()),
                "total_flows": total_flows,
                "ratio_percent": round(float(high_rate_mask.mean()) * 100, 2),
                "avg_flow_packets_per_sec": round(float(flow_packets_s[high_rate_mask].mean()), 2) if int(high_rate_mask.sum()) else 0.0,
                "avg_flow_bytes_per_sec": round(float(flow_bytes_s[high_rate_mask].mean()), 2) if int(high_rate_mask.sum()) else 0.0,
            }
        )

    # =========================================================
    # RULE 3: Port scan
    # =========================================================
    if src_ip_col and dst_port_col:
        scan_df = pd.DataFrame({
            "src_ip": src_ip,
            "dst_port": dst_port,
            "flow_bytes_s": flow_bytes_s,
            "flow_duration": flow_duration,
        })

        portscan_stats = (
            scan_df.groupby("src_ip")
            .agg(
                unique_dst_ports=("dst_port", "nunique"),
                flows=("dst_port", "count"),
                avg_flow_duration=("flow_duration", "mean"),
            )
            .reset_index()
        )

        hits = portscan_stats[
            (portscan_stats["unique_dst_ports"] >= 20) &
            (portscan_stats["flows"] >= 20)
        ].sort_values(["unique_dst_ports", "flows"], ascending=False)

        if not hits.empty:
            top_hit = hits.iloc[0].to_dict()
            _add_rule(
                triggered_rules,
                rule_id="RULE_PORTSCAN_001",
                severity="High",
                title="Possible Port Scan",
                description="One source IP touched many destination ports in a suspicious pattern.",
                evidence={
                    "top_source_ip": top_hit["src_ip"],
                    "unique_dst_ports": int(top_hit["unique_dst_ports"]),
                    "flows": int(top_hit["flows"]),
                    "matched_sources_count": int(len(hits)),
                    "top_sources_preview": hits.head(5).to_dict(orient="records"),
                }
            )

    # =========================================================
    # RULE 4: Brute force attempts
    # =========================================================
    if src_ip_col and dst_ip_col and dst_port_col:
        brute_mask = dst_port.isin(BRUTEFORCE_PORTS)

        brute_df = pd.DataFrame({
            "src_ip": src_ip[brute_mask],
            "dst_ip": dst_ip[brute_mask],
            "dst_port": dst_port[brute_mask],
            "flow_duration": flow_duration[brute_mask],
            "pkt_len_mean": pkt_len_mean[brute_mask],
        })

        if not brute_df.empty:
            brute_stats = (
                brute_df.groupby(["src_ip", "dst_ip", "dst_port"])
                .agg(
                    attempts=("dst_port", "count"),
                    avg_duration=("flow_duration", "mean"),
                    avg_pkt_len=("pkt_len_mean", "mean"),
                )
                .reset_index()
            )

            brute_hits = brute_stats[
                (brute_stats["attempts"] >= 15)
            ].sort_values("attempts", ascending=False)

            if not brute_hits.empty:
                top_hit = brute_hits.iloc[0].to_dict()
                _add_rule(
                    triggered_rules,
                    rule_id="RULE_BRUTEFORCE_001",
                    severity="Medium",
                    title="Possible Brute Force Activity",
                    description="Repeated connections were observed from the same source to the same host/service.",
                    evidence={
                        "top_source_ip": top_hit["src_ip"],
                        "target_ip": top_hit["dst_ip"],
                        "target_port": int(top_hit["dst_port"]),
                        "attempts": int(top_hit["attempts"]),
                        "matched_groups_count": int(len(brute_hits)),
                        "top_groups_preview": brute_hits.head(5).to_dict(orient="records"),
                    }
                )

    # =========================================================
    # RULE 5: Possible beaconing / repeated callback
    # =========================================================
    if src_ip_col and dst_ip_col:
        beacon_df = pd.DataFrame({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "flow_iat_mean": flow_iat_mean,
            "pkt_len_mean": pkt_len_mean,
        })

        beacon_stats = (
            beacon_df.groupby(["src_ip", "dst_ip"])
            .agg(
                flows=("dst_ip", "count"),
                avg_iat=("flow_iat_mean", "mean"),
                std_iat=("flow_iat_mean", "std"),
                avg_pkt_len=("pkt_len_mean", "mean"),
            )
            .reset_index()
        )

        beacon_stats["std_iat"] = beacon_stats["std_iat"].fillna(0.0)

        beacon_hits = beacon_stats[
            (beacon_stats["flows"] >= 20) &
            (beacon_stats["avg_iat"] > 0) &
            (beacon_stats["std_iat"] <= beacon_stats["avg_iat"] * 0.25)
        ].sort_values("flows", ascending=False)

        if not beacon_hits.empty:
            top_hit = beacon_hits.iloc[0].to_dict()
            _add_rule(
                triggered_rules,
                rule_id="RULE_BEACON_001",
                severity="Low",
                title="Possible Periodic Beaconing",
                description="Repeated flows with relatively stable timing were observed between the same peers.",
                evidence={
                    "src_ip": top_hit["src_ip"],
                    "dst_ip": top_hit["dst_ip"],
                    "flows": int(top_hit["flows"]),
                    "avg_iat": round(float(top_hit["avg_iat"]), 2),
                    "std_iat": round(float(top_hit["std_iat"]), 2),
                    "matched_pairs_count": int(len(beacon_hits)),
                    "top_pairs_preview": beacon_hits.head(5).to_dict(orient="records"),
                }
            )

    # --- summary ---
    severity_counts = {
        "High": sum(1 for r in triggered_rules if r["severity"] == "High"),
        "Medium": sum(1 for r in triggered_rules if r["severity"] == "Medium"),
        "Low": sum(1 for r in triggered_rules if r["severity"] == "Low"),
    }

    return {
        "summary": {
            "status": "ok",
            "file": Path(csv_path).name,
            "total_flows": total_flows,
            "triggered_rules": len(triggered_rules),
            "high_severity": severity_counts["High"],
            "medium_severity": severity_counts["Medium"],
            "low_severity": severity_counts["Low"],
        },
        "triggered_rules": triggered_rules,
        "sample_hits": sample_hits[:20],
    }