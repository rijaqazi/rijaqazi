"""Business logic for agent heartbeat processing."""

from datetime import datetime

from ...core.settings import settings


class HeartbeatService:
    def __init__(self, repository):
        self.repository = repository

    def process(self, payload):
        payload = payload if isinstance(payload, dict) else {}
        company_id = str(payload.get("company_id", "")).strip()
        ip_address = str(payload.get("ip_address", "")).strip()
        if not company_id or not ip_address:
            raise ValueError("Missing required fields: company_id and ip_address")
        computer_name = str(payload.get("computer_name", "unknown")).strip() or "unknown"
        public_ip = str(payload.get("public_ip", "unknown")).strip() or "unknown"
        action, server_time = self.repository.record_heartbeat(
            company_id, computer_name, ip_address, public_ip
        )
        return {
            "company_id": company_id, "computer_name": computer_name, "ip_address": ip_address,
            "action": action, "server_time": server_time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def status(self):
        data = self.repository.status()
        data.update({"server": "running", "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        return data

    def recent_heartbeats(self):
        return [self._serialize(record) for record in self.repository.recent_heartbeats()]

    def active_ips(self):
        return [self._serialize(record) for record in self.repository.active_ips()]

    @staticmethod
    def _serialize(record):
        output = {**record}
        output["_id"] = str(output.get("_id", ""))
        for field, value in output.items():
            if isinstance(value, datetime):
                output[field] = value.strftime("%Y-%m-%d %H:%M:%S")
        return output


def create_heartbeat_service():
    from ...repositories.heartbeat_repository import HeartbeatRepository

    return HeartbeatService(HeartbeatRepository(settings.mongodb_uri))
