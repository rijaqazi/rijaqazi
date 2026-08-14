"""MongoDB access for rule generation."""

from ..core.settings import settings
from ..services.rules.rule_policy import find_cvss_entry


class RuleRepository:
    """Read alerts and their associated CVSS records from MongoDB."""

    def __init__(self, client=None):
        if client is not None:
            self.client = client
            return
        if not settings.mongodb_uri:
            raise RuntimeError("MONGODB_URI is not set. Export it before running rule generation.")
        from pymongo import MongoClient

        self.client = MongoClient(settings.mongodb_uri)

    def alerts(self):
        return list(self.client["Alerts"]["Alerts"].find({}))

    def cvss_for_alert(self, source_ip, alert_type):
        return find_cvss_entry(self.client["CVSS"]["cvss"], source_ip, alert_type)
