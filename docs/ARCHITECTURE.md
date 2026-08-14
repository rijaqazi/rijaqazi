# Target Architecture

ThreatSentinel is migrating from independent scripts to a backend package with a versioned API. The migration is intentionally incremental: legacy scripts remain runnable until their logic is moved and tested.

```text
backend/app/
├── api/v1/             HTTP endpoints
├── core/               settings, paths, security, logging
├── integrations/taxii/ TAXII clients and server integration
├── models/             domain models
├── repositories/       MongoDB access
├── services/           alert, scoring, intelligence, rule, report logic
└── workers/            capture and detector processes
```

## Current ownership

| Current module | Future backend location |
|---|---|
| `agent/heartbeat_server.py` | versioned heartbeat API, service, and repository (wrapper retained) |
| remaining `agent/` scripts | agent clients |
| `ioc/taxi_server.py` | `integrations/taxii/server.py` (compatibility wrapper retained) |
| `ioc/push_stix.py`, `ioc/pull_ioc.py` | `integrations/taxii/client.py` (compatibility wrappers retained) |
| `ioc/ioc_db.py` | intelligence STIX-ingestion service and IOC repository (wrapper retained) |
| `cvss/cvss_automation.py` | scoring service and CVSS worker (wrapper retained) |
| remaining `ioc/` scripts | intelligence services |
| `cvss/` | scoring services |
| `Rule_Generation/` | rule and report services |
| `nmap/`, `arp/`, `icmp/`, `new_detection/` | detector workers |

Generated PCAPs, logs, parsed data, STIX bundles, and reports belong under `data/` as each module is migrated.
