"""MongoDB persistence for detector alert imports."""

from ..core.settings import settings


class AlertLogRepository:
    def __init__(self, database, collection, client=None):
        if client is None:
            if not settings.mongodb_uri:
                raise RuntimeError("MONGODB_URI must be set before importing detector alerts.")
            from pymongo import MongoClient

            client = MongoClient(settings.mongodb_uri)
        self.collection = client[database][collection]

    def insert_alerts(self, alerts):
        if not alerts:
            return 0
        return len(self.collection.insert_many(alerts).inserted_ids)
