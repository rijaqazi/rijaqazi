"""Detect ICMP flood and fragmentation attacks from tshark JSON exports."""

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path


DEFAULT_THRESHOLDS = {"echo_flood": 50, "smurf": 20, "timestamp_flood": 20, "mask_flood": 15, "fragment_flood": 10}


def detect_icmp_packets(packets, flood_window=5, thresholds=None):
    """Return one deduplicated alert per ICMP attack type and source IP."""
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    windows = {name: defaultdict(list) for name in DEFAULT_THRESHOLDS}
    alerted, alerts = set(), []

    def record(alert_type, source_ip, timestamps, target_ip, source_mac):
        key = (alert_type, source_ip)
        if key in alerted:
            return
        alerted.add(key)
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        alerts.append(
            {
                "timestamp": time.time(),
                "alert_type": alert_type,
                "type": alert_type,
                "src_ip": source_ip,
                "target_ip": target_ip,
                "src_mac": source_mac,
                "claimed_mac": "N/A",
                "previous_mac": "N/A",
                "ports": [],
                "ports_scanned_count": 0,
                "start_time": time.ctime(min(timestamps)),
                "duration_sec": round(duration, 1),
            }
        )

    def add_window(kind, key, timestamp):
        windows[kind][key].append(timestamp)
        windows[kind][key] = [item for item in windows[kind][key] if timestamp - item <= flood_window]
        return windows[kind][key]

    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        frame, ip_layer, icmp, eth = layers.get("frame", {}), layers.get("ip", {}), layers.get("icmp", {}), layers.get("eth", {})
        try:
            timestamp = float(frame.get("frame.time_epoch", 0))
        except (TypeError, ValueError):
            continue
        source_ip, target_ip = ip_layer.get("ip.src", ""), ip_layer.get("ip.dst", "")
        source_mac, icmp_type = eth.get("eth.src", "N/A"), icmp.get("icmp.type", "")
        if not source_ip or not timestamp:
            continue
        if icmp_type == "8":
            values = add_window("echo_flood", source_ip, timestamp)
            if len(values) >= thresholds["echo_flood"]:
                record("ICMP Echo Request Flood", source_ip, values, target_ip, source_mac)
            if target_ip.endswith(".255"):
                values = add_window("smurf", source_ip, timestamp)
                if len(values) >= thresholds["smurf"]:
                    record("Smurf Attack", source_ip, values, target_ip, source_mac)
        if icmp_type == "13":
            values = add_window("timestamp_flood", source_ip, timestamp)
            if len(values) >= thresholds["timestamp_flood"]:
                record("ICMP Timestamp Request Flood", source_ip, values, target_ip, source_mac)
        if icmp_type == "17":
            values = add_window("mask_flood", source_ip, timestamp)
            if len(values) >= thresholds["mask_flood"]:
                record("ICMP Address Mask Request Flood", source_ip, values, target_ip, source_mac)
        flags = ip_layer.get("ip.flags_tree", {})
        try:
            fragment_offset = int(ip_layer.get("ip.frag_offset", "0"))
        except (TypeError, ValueError):
            fragment_offset = 0
        if icmp_type and (flags.get("ip.flags.mf", "0") == "1" or fragment_offset > 0):
            values = add_window("fragment_flood", (source_ip, target_ip), timestamp)
            if len(values) >= thresholds["fragment_flood"]:
                record("ICMP Fragmentation Flood", source_ip, values, target_ip, source_mac)
    return alerts


def format_alert(alert):
    return (
        f"[ALERT] {alert['alert_type']} from {alert['src_ip']} | Target_IP: {alert['target_ip']} | "
        f"SRC_MAC: {alert['src_mac']} | Claimed_MAC: N/A | Previous_MAC: N/A | Ports: | "
        f"Ports Scanned: 0 | Start: {alert['start_time']} | Duration: {alert['duration_sec']:.1f}s"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", help="Path to Wireshark/tshark JSON export.")
    parser.add_argument("--log", default="icmp_alerts.log")
    parser.add_argument("--json-out", default="icmp_alerts.json")
    args = parser.parse_args()
    try:
        packets = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read packet JSON: {exc}") from exc
    alerts = detect_icmp_packets(packets)
    for alert in alerts:
        message = format_alert(alert)
        print(f"\033[91m{message}\033[0m")
        with open(args.log, "a", encoding="utf-8") as file_handle:
            file_handle.write(message + "\n")
    if alerts:
        Path(args.json_out).write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"Detection complete. Alerts saved to {args.log} and {args.json_out}")


if __name__ == "__main__":
    main()
