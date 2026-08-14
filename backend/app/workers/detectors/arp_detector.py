"""Detect common ARP attacks from tshark JSON packet exports."""

import argparse
import json
import logging
import time
from collections import defaultdict, deque
from pathlib import Path


def _alert_message(alert):
    details = alert["details"]
    return (
        f"{alert['alert_type']} ALERT from {alert['src_ip']}"
        f" | Target_IP: {details['target_ip']}"
        f" | SRC_MAC: {details['src_mac'] or 'N/A'}"
        f" | Claimed_MAC: {details['claimed_mac'] or 'N/A'}"
        f" | Previous_MAC: {details['previous_mac'] or 'N/A'}"
        f" | Ports: | Ports Scanned: 0"
        f" | Start: {details['start_time']}"
        f" | Duration: {details['duration']:.1f}s"
    )


def detect_arp_packets(packets):
    """Return deduplicated ARP attack alerts for packet dictionaries."""
    alerts, timestamps, arp_table = [], defaultdict(list), {}
    mac_to_ips, flood_window, alerted = defaultdict(set), defaultdict(lambda: deque(maxlen=20)), set()

    def add_alert(alert_type, source_ip, source_mac, start_time, duration, target_ip="", claimed_mac="", previous_mac=""):
        key = (alert_type, source_ip, target_ip, source_mac, claimed_mac, str(previous_mac))
        if key in alerted:
            return
        alerted.add(key)
        alerts.append(
            {
                "timestamp": time.time(),
                "alert_type": alert_type,
                "type": alert_type,
                "src_ip": source_ip,
                "details": {
                    "target_ip": target_ip,
                    "src_mac": source_mac or "",
                    "claimed_mac": claimed_mac,
                    "previous_mac": previous_mac,
                    "ports": "",
                    "total_ports": 0,
                    "start_time": start_time,
                    "duration": float(duration),
                },
            }
        )

    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        eth, arp, frame = layers.get("eth", {}), layers.get("arp", {}), layers.get("frame", {})
        source_mac = eth.get("eth.src", "")
        source_ip = arp.get("arp.src.proto_ipv4", "")
        target_ip = arp.get("arp.dst.proto_ipv4", "")
        claimed_mac = arp.get("arp.dst.hw_mac", "")
        if not source_ip:
            continue
        try:
            epoch = float(frame.get("frame.time_epoch", 0))
        except (TypeError, ValueError):
            epoch = 0
        if epoch:
            timestamps[source_ip].append(epoch)
            flood_window[source_ip].append(epoch)
        values = timestamps[source_ip]
        start_time = time.ctime(min(values)) if values else "N/A"
        duration = max(values) - min(values) if len(values) > 1 else 0

        if source_ip in arp_table and arp_table[source_ip] != source_mac:
            add_alert("ARP_SPOOF", source_ip, source_mac, start_time, duration, target_ip, claimed_mac, arp_table[source_ip])
        if source_ip == target_ip and claimed_mac:
            add_alert("GRATUITOUS_ARP", source_ip, source_mac, start_time, duration, target_ip, claimed_mac)
        if claimed_mac.lower() == "ff:ff:ff:ff:ff:ff" or target_ip == "255.255.255.255":
            add_alert("BROADCAST_SPOOF", source_ip, source_mac, start_time, duration, target_ip, claimed_mac)
        if len(flood_window[source_ip]) >= 5 and flood_window[source_ip][-1] - flood_window[source_ip][0] < 3:
            add_alert("ARP_FLOOD", source_ip, source_mac, start_time, duration, target_ip)
        if source_mac:
            mac_to_ips[source_mac].add(source_ip)
            if len(mac_to_ips[source_mac]) > 1:
                add_alert("MAC_CONFLICT", source_ip, source_mac, start_time, duration, target_ip, claimed_mac)
        if source_ip == target_ip and arp_table.get(target_ip) and arp_table[target_ip] != source_mac:
            add_alert("CACHE_OVERRIDE", source_ip, source_mac, start_time, duration, target_ip, claimed_mac, arp_table[target_ip])
        if target_ip in arp_table and arp_table[target_ip] != source_mac:
            add_alert("ARP_MITM", source_ip, source_mac, start_time, duration, target_ip, claimed_mac, arp_table[target_ip])
        arp_table.setdefault(source_ip, source_mac)
    return alerts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", help="Path to Wireshark/tshark JSON export.")
    parser.add_argument("--log", help="Path for alert logs.")
    parser.add_argument("--json-out", help="Path for JSON alerts.")
    args = parser.parse_args()
    try:
        packets = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read packet JSON: {exc}") from exc
    alerts = detect_arp_packets(packets)
    logger = logging.getLogger("arp_detector")
    if args.log:
        handler = logging.FileHandler(args.log)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    for alert in alerts:
        message = _alert_message(alert)
        print(f"\033[91m{message}\033[0m")
        if args.log:
            logger.info(message)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(alerts, indent=2), encoding="utf-8")
        print(f"Alerts saved to {args.json_out}")
    print(f"ARP analysis complete. Total alerts: {len(alerts)}")


if __name__ == "__main__":
    main()
