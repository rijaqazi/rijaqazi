"""MongoDB repository for normalized IOC records."""

from pymongo import MongoClient


class IOCRepository:
    """Persist STIX objects while retaining their source bundle identifier."""

    def __init__(self, mongodb_uri):
        if not mongodb_uri:
            raise RuntimeError("MONGODB_URI must be set before using the IOC repository.")
        self.client = MongoClient(mongodb_uri)
        self.collection = self.client["ioc_database"]["Indicator_of_Compromise"]

    def existing_bundle_ids(self):
        return set(self.collection.distinct("bundle_id"))

    def bundle_exists(self, bundle_id):
        return self.collection.find_one({"bundle_id": bundle_id}) is not None

    def insert_bundle_objects(self, bundle_id, objects):
        records = [{"bundle_id": bundle_id, **obj} for obj in objects if isinstance(obj, dict)]
        if records:
            self.collection.insert_many(records, ordered=True)
        return len(records)
