"""MongoDB reads and idempotent writes for organization intelligence sync."""

from ..core.settings import settings


class OrganizationSyncRepository:
    def __init__(self, client=None, organization_database=None):
        if client is None:
            if not settings.mongodb_uri:
                raise RuntimeError("MONGODB_URI must be set before organization synchronization.")
            from pymongo import MongoClient

            client = MongoClient(settings.mongodb_uri)
        self.client = client
        self.security_db = client["security_db"]
        self.alerts_db = client["Alerts"]
        self.cvss_db = client["CVSS"]
        self.ioc_db = client["ioc_database"]
        self.org_db = client[organization_database or settings.organization_database]

    def active_ips(self):
        return [
            document.get("ip_address") or document.get("local_ip")
            for document in self.security_db["ip_tracking"].find({"status": "active"})
            if document.get("ip_address") or document.get("local_ip")
        ]

    def alerts(self):
        records = []
        for name in ("alerts", "Alerts", "threats", "alert", "incidents"):
            if name in self.alerts_db.list_collection_names():
                records.extend(self.alerts_db[name].find())
        return records

    def cvss_entries(self):
        return list(self.cvss_db["cvss"].find()) if "cvss" in self.cvss_db.list_collection_names() else []

    def iocs(self):
        collection = self.ioc_db["Indicator_of_Compromise"]
        return list(collection.find()) if "Indicator_of_Compromise" in self.ioc_db.list_collection_names() else []

    def _save_unique(self, collection_name, document):
        collection = self.org_db[collection_name]
        if collection.find_one({"_id": document["_id"]}):
            return False
        collection.insert_one(document)
        return True

    def save_alert(self, document):
        return self._save_unique("alerts", document)

    def save_cvss(self, document):
        return self._save_unique("cvss", document)

    def save_ioc(self, document):
        return self._save_unique("iocs", document)
