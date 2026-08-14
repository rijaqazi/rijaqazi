"""MongoDB repository for agent heartbeat and IP-tracking records."""

from datetime import datetime

from pymongo import MongoClient


class HeartbeatRepository:
    def __init__(self, mongodb_uri):
        if not mongodb_uri:
            raise RuntimeError("MONGODB_URI must be set before using heartbeat storage.")
        self.client = MongoClient(mongodb_uri)
        database = self.client["security_db"]
        self.ip_tracking = database["ip_tracking"]
        self.heartbeat_logs = database["heartbeat_logs"]

    def record_heartbeat(self, company_id, computer_name, ip_address, public_ip):
        current_time = datetime.now()
        self.ip_tracking.update_many(
            {"company_id": company_id, "status": "active", "ip_address": {"$ne": ip_address}},
            {"$set": {"end_time": current_time, "status": "inactive", "last_updated": current_time}},
        )
        active_record = self.ip_tracking.find_one(
            {"company_id": company_id, "ip_address": ip_address, "status": "active"}
        )
        if active_record:
            self.ip_tracking.update_one(
                {"_id": active_record["_id"]},
                {"$set": {"last_updated": current_time, "public_ip": public_ip}},
            )
            action = "updated"
        else:
            self.ip_tracking.insert_one(
                {
                    "company_id": company_id, "computer_name": computer_name,
                    "ip_address": ip_address, "public_ip": public_ip,
                    "start_time": current_time, "end_time": None, "last_updated": current_time,
                    "status": "active", "first_seen": current_time,
                }
            )
            action = "added"
        self.heartbeat_logs.insert_one(
            {
                "company_id": company_id, "computer_name": computer_name,
                "local_ip": ip_address, "public_ip": public_ip, "timestamp": current_time,
                "action": action, "received_at": current_time,
            }
        )
        return action, current_time

    def status(self):
        try:
            self.client.admin.command("ping")
            mongo_status = "connected"
        except Exception:
            mongo_status = "disconnected"
        return {
            "mongodb": mongo_status,
            "active_ips": self.ip_tracking.count_documents({"status": "active"}),
            "total_heartbeats": self.heartbeat_logs.count_documents({}),
        }

    def recent_heartbeats(self, limit=20):
        return list(self.heartbeat_logs.find().sort("timestamp", -1).limit(limit))

    def active_ips(self):
        return list(self.ip_tracking.find({"status": "active"}).sort("last_updated", -1))
