"""Pure rule-generation policy shared by the legacy worker and future APIs."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional


ACTIONABLE_PRIORITIES = {"critical", "high", "medium"}


def decide_action(alert: Dict[str, Any], _cvss_entry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Choose a defensive action based on a normalized alert type."""
    alert_type = alert.get("alert_type", "") or ""
    alert_type_upper = alert_type.upper()
    source_ip = alert.get("src_ip")
    source_mac = alert.get("src_mac", "N/A")
    action, target, reason, confidence = "notify", source_ip, "Monitoring only", "low"

    if "ARP" in alert_type_upper:
        if "SPOOF" in alert_type_upper or "MITM" in alert_type_upper:
            action, target, reason, confidence = "quarantine_mac", source_mac, "ARP spoofing / MITM detected", "high"
        elif "FLOOD" in alert_type_upper or "BROADCAST" in alert_type_upper:
            action, target, reason, confidence = "block_ip", source_ip, "ARP flood detected", "high"
        elif "GRATUITOUS" in alert_type_upper:
            action, target, reason, confidence = "notify", source_ip, "Gratuitous ARP detected", "medium"
        elif "MAC_CONFLICT" in alert_type_upper or "MAC DUPLICATE" in alert_type_upper:
            action, target, reason, confidence = "notify", source_ip, "MAC conflict / duplicate detected", "medium"
        else:
            action, target, reason, confidence = "notify", source_ip, "ARP anomaly detected", "medium"
    elif "ICMP ADDRESS MASK" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "ICMP Address Mask Request Flood", "high"
    elif "ICMP TIMESTAMP" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "ICMP Timestamp Request Flood", "high"
    elif "ICMP ECHO" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "ICMP Echo Request Flood", "high"
    elif "ICMP FRAGMENT" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "ICMP Fragmentation Flood", "high"
    elif "SMURF" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "ICMP Smurf Attack detected", "high"
    elif "ICMP" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "ICMP anomaly", "medium"
    elif "NULL_SCAN" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "NULL Scan detected", "medium"
    elif "FIN_SCAN" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "FIN Scan detected", "medium"
    elif "XMAS_SCAN" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "XMAS Scan detected", "medium"
    elif "SYN_SCAN" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "SYN Scan detected", "medium"
    elif "UDP_SCAN" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "UDP Scan detected", "medium"
    elif "FULL_PORT_SCAN" in alert_type_upper or "FULLPORT" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "Full Port Scan detected", "medium"
    elif "OS_FINGERPRINT" in alert_type_upper:
        action, target, reason, confidence = "notify", source_ip, "OS Fingerprinting detected", "medium"
    elif "ACK_SCAN" in alert_type_upper or "ACK-SCAN" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "ACK Scan detected", "medium"
    elif "SPOOFED_SYN_FLOOD" in alert_type_upper:
        action, target, reason, confidence = "block_ip", source_ip, "Spoofed SYN Flood detected", "high"

    return {
        "normalized_attack": alert_type,
        "action": action,
        "target": target,
        "reason": reason,
        "confidence": confidence,
        "expiry_seconds": 14400,
    }


def find_cvss_entry(cvss_collection, source_ip: str, alert_type: str):
    """Find the closest CVSS record, accepting space/underscore variants."""
    if not alert_type:
        return None
    for candidate in (alert_type, alert_type.replace(" ", "_"), alert_type.replace("_", " ")):
        entry = cvss_collection.find_one({"source_ip": source_ip, "attack_type": candidate})
        if entry:
            return entry
    matches = list(cvss_collection.find({"source_ip": source_ip}))
    return max(matches, key=lambda entry: float(entry.get("cvss_score", 0)), default=None)


def infer_protocol(alert: Dict[str, Any]) -> str:
    protocol = alert.get("protocol")
    if protocol and protocol != "unknown":
        return protocol
    alert_type = (alert.get("alert_type") or "").upper()
    if "ARP" in alert_type:
        return "ARP"
    if "ICMP" in alert_type:
        return "ICMP"
    if "UDP" in alert_type:
        return "UDP"
    if "FULL_PORT" in alert_type:
        return "TCP/UDP"
    if any(value in alert_type for value in ("SYN", "FIN", "NULL", "XMAS", "ACK", "RST", "SERVICE", "FINGERPRINT")):
        return "TCP"
    return "unknown"


def build_rule(
    alert: Dict[str, Any], cvss_entry: Dict[str, Any], decision: Dict[str, Any], rule_id: str, created: Optional[datetime] = None
) -> Dict[str, Any]:
    """Create the persisted JSON representation of a defensive rule."""
    source_ip = alert.get("src_ip")
    timestamp = created or datetime.now(timezone.utc)
    return {
        "rule_id": rule_id,
        "created": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_alert_id": str(alert.get("_id")),
        "alert_type": alert.get("alert_type") or "",
        "src_ip": source_ip,
        "dst_ip": alert.get("target_ip", "unknown"),
        "protocol": infer_protocol(alert),
        "ports": alert.get("ports", []),
        "ports_scanned_count": alert.get("ports_scanned_count", 0),
        "duration_": alert.get("duration_sec"),
        "cvss_score": float(cvss_entry.get("cvss_score", 0)),
        "priority": cvss_entry.get("priority", "Unknown"),
        "decision": decision,
        "suggested_commands": [
            f"iptables -I INPUT -s {source_ip} -j DROP # temp block",
            f'netsh advfirewall firewall add rule name="Block_{source_ip}" dir=in action=block remoteip={source_ip}',
        ],
    }
