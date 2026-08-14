"""Continuously transfer organization-relevant intelligence from MongoDB."""

import argparse
import time

from ..core.settings import settings
from ..repositories.organization_sync_repository import OrganizationSyncRepository
from ..services.intelligence.organization_sync import build_sync_plan


class OrganizationSyncWorker:
    def __init__(self, repository):
        self.repository = repository

    def run_once(self):
        active_ips = self.repository.active_ips()
        if not active_ips:
            return {"active_ips": [], "alerts": 0, "cvss": 0, "iocs": 0, "saved": 0}
        plan = build_sync_plan(active_ips, self.repository.alerts(), self.repository.cvss_entries(), self.repository.iocs())
        saved = sum(self.repository.save_alert(document) for document in plan["alerts"])
        saved += sum(self.repository.save_cvss(document) for document in plan["cvss"])
        saved += sum(self.repository.save_ioc(document) for document in plan["iocs"])
        return {
            "active_ips": active_ips,
            "alerts": len(plan["alerts"]),
            "cvss": len(plan["cvss"]),
            "iocs": len(plan["iocs"]),
            "saved": saved,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Run one synchronization cycle then exit.")
    parser.add_argument("--interval", type=int, default=settings.organization_sync_poll_seconds)
    args = parser.parse_args()
    if args.interval <= 0:
        raise RuntimeError("--interval must be positive.")
    worker = OrganizationSyncWorker(OrganizationSyncRepository())
    while True:
        try:
            summary = worker.run_once()
            print(f"Active IPs: {', '.join(summary['active_ips']) or 'None'}")
            print(f"Matched alerts={summary['alerts']}, CVSS={summary['cvss']}, IOCs={summary['iocs']}; saved={summary['saved']}")
        except Exception as exc:
            print(f"[x] Organization sync failed: {exc}")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
