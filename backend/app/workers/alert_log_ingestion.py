"""Import normalized detector alert logs into MongoDB."""

import argparse
from pathlib import Path

from ..repositories.alert_log_repository import AlertLogRepository
from ..services.alerts.alert_log_parser import parse_alert_log


def import_alert_log(log_path, database, collection, repository=None):
    alerts = parse_alert_log(log_path)
    repository = repository or AlertLogRepository(database, collection)
    return repository.insert_alerts(alerts), len(alerts)


def main(default_log=None, default_database="Alerts", default_collection="Alerts"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", default=str(default_log) if default_log else None, required=default_log is None)
    parser.add_argument("--database", default=default_database)
    parser.add_argument("--collection", default=default_collection)
    args = parser.parse_args()
    count, parsed = import_alert_log(Path(args.log), args.database, args.collection)
    print(f"Imported {count} of {parsed} parsed alert(s) into {args.database}.{args.collection}.")


if __name__ == "__main__":
    main()
