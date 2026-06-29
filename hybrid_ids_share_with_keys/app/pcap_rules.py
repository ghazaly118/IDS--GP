import dpkt
import socket
import time
import re
import urllib.parse
from collections import defaultdict, deque, Counter
from pathlib import Path


SIGNATURES = {
    "web_attack": [
        r"select", r"union", r"insert", r"update", r"delete",
        r"<script>", r"</script>", r"alert\(", r"prompt\(",
        r"\.\./", r"/etc/passwd",
        r"xp_cmdshell", r"drop\s+table",
        r"javascript:", r"%3cscript%3e",
        r"1=1", r"--", r"' or '1'='1"
    ],
    "brute_force": [
        r"username=", r"password=", r"login", r"signin", r"auth", r"passwd",
        r"loginattempt", r"authentication failed", r"pass=", r"user=", r"logon"
    ],
    "botnet": [
        r"botnet", r"c2", r"command and control", r"payload", r"attack server", r"malware"
    ]
}

PRECOMPILED_SIGS = {
    atype: [re.compile(sig, re.IGNORECASE) for sig in sig_list]
    for atype, sig_list in SIGNATURES.items()
}

WINDOW_SIZE = 2.0
PORTSCAN_THRESHOLD = 15
MIN_DOS_PER_IP = 50
MIN_DOS_AGG = 200
MAX_SAMPLE_ALERTS = 25


def normalize_payload(payload_bytes: bytes) -> str:
    text = payload_bytes.decode(errors="ignore")
    text = urllib.parse.unquote_plus(text)
    text = text.lower()
    text = " ".join(text.split())
    return text


def _ip_to_str(addr: bytes) -> str:
    try:
        if len(addr) == 4:
            return socket.inet_ntoa(addr)
        return socket.inet_ntop(socket.AF_INET6, addr)
    except Exception:
        return "unknown"


def _open_reader(file_obj):
    try:
        return dpkt.pcap.Reader(file_obj)
    except Exception:
        file_obj.seek(0)
        return dpkt.pcapng.Reader(file_obj)


def compute_dos_thresholds(pcap_file: str, factor_per_ip: float = 0.05, factor_total: float = 0.1):
    packet_times = []

    with open(pcap_file, "rb") as f:
        reader = _open_reader(f)
        for ts, _ in reader:
            packet_times.append(ts)

    if not packet_times:
        return MIN_DOS_PER_IP, MIN_DOS_AGG, 0.0

    duration = max(packet_times) - min(packet_times)
    duration = max(duration, 1.0)
    avg_rate = len(packet_times) / duration

    per_ip_thresh = max(MIN_DOS_PER_IP, int(avg_rate * factor_per_ip))
    agg_thresh = max(MIN_DOS_AGG, int(avg_rate * factor_total))

    return per_ip_thresh, agg_thresh, avg_rate


def _append_sample(sample_alerts: list, alert: dict):
    if len(sample_alerts) < MAX_SAMPLE_ALERTS:
        sample_alerts.append(alert)


def run_pcap_rules(pcap_file: str):
    pcap_file = str(Path(pcap_file))
    counts = defaultdict(int)
    source_alert_counts = Counter()
    total_alerts = 0
    packet_counter = 0
    sample_alerts = []

    ip_packet_times = defaultdict(deque)
    ip_ports = defaultdict(lambda: defaultdict(deque))
    last_dos_alert_time = defaultdict(lambda: 0.0)
    last_agg_dos_alert = 0.0
    last_portscan_alert_time = defaultdict(lambda: 0.0)

    dos_threshold, dos_agg_threshold, avg_rate = compute_dos_thresholds(pcap_file)

    start_time = time.time()

    with open(pcap_file, "rb") as f:
        reader = _open_reader(f)

        for timestamp, buf in reader:
            packet_counter += 1

            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                transport = ip.data
                if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    continue

                src_ip = _ip_to_str(ip.src)
                dst_ip = _ip_to_str(ip.dst)
                payload = transport.data if hasattr(transport, "data") else b""

                # -----------------------
                # Signature-based detection
                # -----------------------
                if payload:
                    payload_text = normalize_payload(payload)

                    for atype, regex_list in PRECOMPILED_SIGS.items():
                        matched = False
                        for regex in regex_list:
                            if regex.search(payload_text):
                                counts[atype] += 1
                                total_alerts += 1
                                source_alert_counts[src_ip] += 1
                                _append_sample(sample_alerts, {
                                    "type": atype,
                                    "source": "signature",
                                    "msg": f"{atype.replace('_', ' ').title()} signature matched",
                                    "src": src_ip,
                                    "dst": dst_ip,
                                })
                                matched = True
                                break
                        if matched:
                            continue

                # -----------------------
                # Sliding-window per-IP packet times
                # -----------------------
                ip_packet_times[src_ip].append(timestamp)
                while ip_packet_times[src_ip] and ip_packet_times[src_ip][0] < timestamp - WINDOW_SIZE:
                    ip_packet_times[src_ip].popleft()

                if len(ip_packet_times[src_ip]) >= dos_threshold:
                    if timestamp - last_dos_alert_time[src_ip] >= WINDOW_SIZE:
                        counts["dos"] += 1
                        total_alerts += 1
                        source_alert_counts[src_ip] += 1
                        last_dos_alert_time[src_ip] = timestamp
                        _append_sample(sample_alerts, {
                            "type": "dos",
                            "source": "heuristic",
                            "msg": "Per-IP DoS burst detected",
                            "src": src_ip,
                            "dst": dst_ip,
                        })

                total_packets_in_window = sum(len(q) for q in ip_packet_times.values())
                if total_packets_in_window >= dos_agg_threshold:
                    if timestamp - last_agg_dos_alert >= WINDOW_SIZE:
                        counts["dos"] += 1
                        total_alerts += 1
                        last_agg_dos_alert = timestamp
                        _append_sample(sample_alerts, {
                            "type": "dos",
                            "source": "heuristic",
                            "msg": "Aggregated DoS burst detected",
                            "src": src_ip,
                            "dst": dst_ip,
                        })

                # -----------------------
                # Port Scan detection
                # -----------------------
                dport = getattr(transport, "dport", None)
                if dport is not None:
                    ports_deque = ip_ports[src_ip][int(dport)]
                    ports_deque.append(timestamp)

                    while ports_deque and ports_deque[0] < timestamp - WINDOW_SIZE:
                        ports_deque.popleft()

                    active_ports = sum(1 for dq in ip_ports[src_ip].values() if dq)

                    if active_ports >= PORTSCAN_THRESHOLD:
                        if timestamp - last_portscan_alert_time[src_ip] >= WINDOW_SIZE:
                            counts["port_scan"] += 1
                            total_alerts += 1
                            source_alert_counts[src_ip] += 1
                            last_portscan_alert_time[src_ip] = timestamp
                            _append_sample(sample_alerts, {
                                "type": "port_scan",
                                "source": "heuristic",
                                "msg": "Port scan behavior detected",
                                "src": src_ip,
                                "dst": dst_ip,
                            })

            except Exception:
                continue

    processing_time = round(time.time() - start_time, 2)

    ordered_types = ["web_attack", "brute_force", "botnet", "dos", "port_scan"]
    attack_type_summary = {k: int(counts[k]) for k in ordered_types}

    top_sources = [
        {"src": ip, "count": cnt}
        for ip, cnt in source_alert_counts.most_common(10)
    ]

    return {
        "status": "ok",
        "engine": "dpkt_pcap_rules",
        "pcap_file": Path(pcap_file).name,
        "message": "Packet rules executed in parallel with the AI pipeline.",
        "summary": {
            "total_alerts": int(total_alerts),
            "packets_processed": int(packet_counter),
            "processing_time_sec": processing_time,
            "window_size_sec": WINDOW_SIZE,
            "dos_threshold_per_ip": int(dos_threshold),
            "dos_threshold_aggregated": int(dos_agg_threshold),
            "average_packet_rate": round(float(avg_rate), 2),
            "attack_type_summary": attack_type_summary,
            "top_sources": top_sources,
        },
        "sample_alerts": sample_alerts,
    }