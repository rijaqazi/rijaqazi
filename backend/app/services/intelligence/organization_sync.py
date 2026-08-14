"""Match relevant global intelligence to organization endpoints."""

import re


IP_PATTERN = r"(\d{1,3}(?:\.\d{1,3}){3})"


def extract_source_ip_from_raw_alert(raw_alert):
    match = re.search(rf"\|?\s*from\s*{IP_PATTERN}\s*\|?", raw_alert or "")
    return match.group(1) if match else None


def extract_target_ip_from_raw_alert(raw_alert):
    match = re.search(rf"\|?\s*Target_IP:\s*{IP_PATTERN}\s*\|?", raw_alert or "")
    return match.group(1) if match else None


def _deduplicate(documents):
    seen = set()
    result = []
    for document in documents:
        key = str(document.get("_id", id(document)))
        if key not in seen:
            seen.add(key)
            result.append(document)
    return result


def build_sync_plan(active_ips, alerts, cvss_entries, iocs):
    """Return organization-scoped alerts, CVSS entries, and IOCs to transfer."""
    active_ips = set(active_ips)
    iocs_by_ip = {ioc.get("ip_address"): ioc for ioc in iocs if ioc.get("ip_address")}
    matched_alerts, matched_cvss, matched_iocs = [], [], []

    for alert in alerts:
        target_ip = alert.get("target_ip")
        if target_ip in active_ips:
            matched_alerts.append(alert)
            if target_ip in iocs_by_ip:
                matched_iocs.append(iocs_by_ip[target_ip])

    for cvss in cvss_entries:
        target_ip = cvss.get("target_ip") or extract_target_ip_from_raw_alert(cvss.get("raw_alert"))
        if target_ip in active_ips:
            matched_cvss.append(cvss)
            source_ip = cvss.get("source_ip") or extract_source_ip_from_raw_alert(cvss.get("raw_alert"))
            if source_ip in iocs_by_ip:
                matched_iocs.append(iocs_by_ip[source_ip])

    return {
        "alerts": _deduplicate(matched_alerts),
        "cvss": _deduplicate(matched_cvss),
        "iocs": _deduplicate(matched_iocs),
    }
