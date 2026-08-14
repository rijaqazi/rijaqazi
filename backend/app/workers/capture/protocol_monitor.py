"""Protocol-aware live TShark monitor that writes suspicious captures to data/captures."""

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from ...core.settings import settings


DISPLAY_FILTER = "(tcp.flags.syn==1 && tcp.flags.ack==0) || icmp.type==8 || arp.opcode==2 || tcp || udp || arp || icmp"
FIELD_ARGS = [
    "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
    "-e", "eth.src", "-e", "tcp.flags", "-e", "tcp.dstport", "-e", "udp.dstport",
    "-e", "icmp.type", "-e", "arp.opcode", "-E", "separator=|", "-E", "quote=n", "-l",
]
MAC_ADDRESS = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
THRESHOLDS = {
    "syn": 5, "fin": 5, "xmas": 5, "null": 5, "ack": 10, "udp": 10,
    "rst": 30, "icmp_echo": 50, "icmp_timestamp": 20, "icmp_mask": 15,
    "arp": 10, "mac_conflict": 2,
}


def safe_bpf(source):
    """Return a BPF expression only for a valid IP or MAC address."""
    try:
        return f"host {ipaddress.ip_address(source)}"
    except ValueError:
        if MAC_ADDRESS.fullmatch(source):
            return f"ether host {source.lower()}"
    raise ValueError(f"Unsafe source address from packet stream: {source!r}")


def stream_command(interface, tshark="tshark"):
    return [tshark, "-i", interface, "-Y", DISPLAY_FILTER, *FIELD_ARGS]


def capture_command(interface, source, output_file, packet_limit, tshark="tshark"):
    return [tshark, "-i", interface, "-f", safe_bpf(source), "-c", str(packet_limit), "-w", str(output_file)]


class ProtocolMonitor:
    """Stateful threshold detector for rows emitted by :func:`stream_command`."""

    def __init__(self, window_seconds=10, cooldown_seconds=5, thresholds=None):
        self.window = window_seconds
        self.cooldown = cooldown_seconds
        self.thresholds = {**THRESHOLDS, **(thresholds or {})}
        self.ports = defaultdict(lambda: defaultdict(set))
        self.times = defaultdict(lambda: defaultdict(deque))
        self.mac_to_ips = defaultdict(set)
        self.last_trigger = {}

    def _trim(self, values, now):
        while values and values[0] < now - self.window:
            values.popleft()

    def _event_reason(self, source, ethernet, tcp_flags, tcp_port, udp_port, icmp_type, arp_opcode, now):
        flags = tcp_flags.lower()
        is_syn = "0x02" in flags or ("s" in flags and "a" not in flags)
        is_fin = "0x01" in flags or "f" in flags
        is_rst = "0x04" in flags or "r" in flags
        is_ack = "0x10" in flags or "a" in flags
        is_psh = "0x08" in flags or "p" in flags
        is_urg = "0x20" in flags or "u" in flags
        ports = self.ports[source]
        times = self.times[source]

        if tcp_port:
            if is_syn and not is_ack:
                ports["syn"].add(tcp_port)
            elif is_fin and not is_ack:
                ports["xmas" if is_psh and is_urg else "fin"].add(tcp_port)
            elif not any((is_syn, is_ack, is_fin, is_rst, is_psh, is_urg)):
                ports["null"].add(tcp_port)
            elif is_ack and not is_syn:
                ports["ack"].add(tcp_port)
        if udp_port:
            ports["udp"].add(udp_port)
        if is_rst:
            times["rst"].append(now)
            self._trim(times["rst"], now)
        icmp_key = {"8": "icmp_echo", "13": "icmp_timestamp", "17": "icmp_mask"}.get(icmp_type)
        if icmp_key:
            times[icmp_key].append(now)
            self._trim(times[icmp_key], now)
        if arp_opcode.strip() == "2":
            times["arp"].append(now)
            self._trim(times["arp"], now)
            if ethernet and source:
                self.mac_to_ips[ethernet.lower()].add(source)

        for key, label in (("syn", "SYN_SCAN"), ("fin", "FIN_SCAN"), ("xmas", "XMAS_SCAN"),
                           ("null", "NULL_SCAN"), ("ack", "ACK_SCAN"), ("udp", "UDP_SCAN")):
            if len(ports[key]) >= self.thresholds[key]:
                return f"{label} ({len(ports[key])} ports)"
        for key, label in (("rst", "RST_FLOOD"), ("icmp_echo", "ICMP_ECHO_FLOOD"),
                           ("icmp_timestamp", "ICMP_TIMESTAMP_FLOOD"), ("icmp_mask", "ICMP_MASK_FLOOD"),
                           ("arp", "ARP_FLOOD")):
            if len(times[key]) >= self.thresholds[key]:
                return f"{label} ({len(times[key])})"
        if ethernet and len(self.mac_to_ips[ethernet.lower()]) >= self.thresholds["mac_conflict"]:
            return f"MAC_CONFLICT ({len(self.mac_to_ips[ethernet.lower()])} IPs)"
        return None

    def process_line(self, line):
        """Return an alert dict when a threshold is newly exceeded, otherwise ``None``."""
        fields = line.strip().split("|")
        fields += [""] * (9 - len(fields))
        try:
            timestamp = float(fields[0]) if fields[0] else time.time()
        except ValueError:
            timestamp = time.time()
        source, ethernet = fields[1] or fields[3], fields[3]
        if not source:
            return None
        reason = self._event_reason(source, ethernet, *fields[4:9], timestamp)
        if not reason or timestamp - self.last_trigger.get(source, 0) < self.cooldown:
            return None
        self.last_trigger[source] = timestamp
        return {"time": int(timestamp), "src": source, "reason": reason}


def write_alert(capture_dir, alert):
    capture_dir = Path(capture_dir)
    capture_dir.mkdir(parents=True, exist_ok=True)
    with (capture_dir / "alerts.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps(alert) + "\n")


def capture_alert(interface, capture_dir, packet_limit, alert, tshark="tshark", runner=subprocess.run):
    capture_dir = Path(capture_dir)
    safe_source = re.sub(r"[^A-Za-z0-9._-]", "_", alert["src"])
    output_file = capture_dir / f"auto_{safe_source}_{alert['time']}.pcap"
    command = capture_command(interface, alert["src"], output_file, packet_limit, tshark)
    runner(command, check=False)
    alert["capture_file"] = str(output_file)
    write_alert(capture_dir, alert)
    return output_file


def run_monitor(interface, capture_dir, packet_limit, window_seconds, cooldown_seconds, tshark="tshark", popen=subprocess.Popen):
    if not shutil.which(tshark):
        raise RuntimeError("tshark was not found. Install it before starting the live capture monitor.")
    monitor = ProtocolMonitor(window_seconds, cooldown_seconds)
    process = popen(stream_command(interface, tshark), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in process.stdout:
            alert = monitor.process_line(line)
            if alert:
                print(f"[!] {alert['reason']} from {alert['src']}; capturing evidence.")
                threading.Thread(target=capture_alert, args=(interface, capture_dir, packet_limit, alert, tshark), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        if process.poll() is None:
            process.terminate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default=settings.capture_interface, help="Network interface to monitor.")
    parser.add_argument("--capture-dir", default=str(settings.capture_input_dir))
    parser.add_argument("--packet-limit", type=int, default=settings.capture_packet_limit)
    parser.add_argument("--window", type=int, default=settings.capture_window_seconds)
    parser.add_argument("--cooldown", type=int, default=settings.capture_cooldown_seconds)
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args()
    if not args.interface:
        raise SystemExit("Provide --interface or set CAPTURE_INTERFACE in .env.")
    if min(args.packet_limit, args.window, args.cooldown) <= 0:
        raise SystemExit("--packet-limit, --window, and --cooldown must be positive.")
    run_monitor(args.interface, args.capture_dir, args.packet_limit, args.window, args.cooldown, args.tshark)


if __name__ == "__main__":
    main()
