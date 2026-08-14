"""Pure risk and enrichment helpers for generated rule reports."""


def compute_risk(cvss_score, related_count, reputation_score=0.5, asset_criticality=0.5):
    """Compute the existing weighted 0-100 risk score used by reports."""
    cvss_normalized = (cvss_score or 0) / 10.0
    frequency_normalized = min(related_count, 10) / 10.0
    score = (
        cvss_normalized * 0.50
        + frequency_normalized * 0.30
        + reputation_score * 0.15
        + asset_criticality * 0.05
    ) * 100.0
    return round(score, 1)


def risk_category(score):
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def normalize_ipinfo(ipinfo_data):
    """Normalize public-IP enrichment without mutating or self-referencing input."""
    if not ipinfo_data:
        return None
    if "bogon" in ipinfo_data:
        return {"country": "Private Network", "city": "Internal", "org": None, "raw": dict(ipinfo_data)}
    normalized = dict(ipinfo_data)
    normalized["raw"] = dict(ipinfo_data)
    return normalized
