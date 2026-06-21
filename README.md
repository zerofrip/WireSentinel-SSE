# WireSentinel-SSE

Phase 16 Secure Service Edge layer for WireSentinel.

## Crates

| Crate | Purpose |
|-------|---------|
| `sse-core` | Core types, security policy, errors |
| `swg` | Secure Web Gateway — URL categorization and web policies |
| `casb` | Cloud Access Security Broker — SaaS providers and shadow IT |
| `dlp` | Data Loss Prevention — pattern detection and incidents |
| `browser-isolation` | Remote/containerized browser isolation sessions |
| `threat-protection` | Threat feeds and IOC matching |
| `ueba` | User and entity behavior analytics |
| `risk-engine` | Continuous risk score synthesis |
| `datalake` | Security event lake with retention policies |
| `siem` | SIEM exporters (Splunk, Sentinel, Elastic, OpenSearch, QRadar, Syslog) |
| `sdk` | SSE plugin trait and manifest |
| `controller` | Controller telemetry and incident bundle DTOs |

## Build

```bash
cargo test --workspace
```

Requires `WireSentinel/shared-types` as a sibling repository.
