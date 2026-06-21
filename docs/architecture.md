# WireSentinel-SSE Architecture

Phase 16 Secure Service Edge — SWG, CASB, DLP, browser isolation, threat protection, UEBA, risk scoring, data lake, and SIEM export.

## Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        WireSentinel Agent                             │
│  ┌─────┐ ┌──────┐ ┌─────┐ ┌──────────────┐ ┌──────────┐ ┌──────────┐ │
│  │ swg │ │ casb │ │ dlp │ │ browser-iso  │ │  threat  │ │   ueba   │ │
│  └──┬──┘ └──┬───┘ └──┬──┘ └──────┬───────┘ └────┬─────┘ └────┬─────┘ │
│     │       │        │           │              │            │       │
│  ┌──┴───────┴────────┴───────────┴──────────────┴────────────┴─────┐ │
│  │ risk-engine · datalake · siem · sdk                              │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
                              │
                    SseTelemetryPayload
                    SseIncidentBundleDto
                              │
                              ▼
                   WireSentinel-Controller
```

## Core abstractions

### `SecureWebGateway`

URL categorization, domain reputation, and `WebPolicy` enforcement. Emits `WebAccessAllowed` / `WebAccessBlocked` / `WebAccessViolation` via `shared-types` events.

### `CasbEngine`

Registers `CasbProvider` implementations (M365, Google, Slack, GitHub, Dropbox, Box, Salesforce, Generic mock). Detects shadow IT and CASB violations.

### `DlpEngine`

Applies `DlpPolicy` rules with pattern detection: credit card (Luhn), API keys, SSN/email/phone PII regex.

### `BrowserIsolationEngine`

Manages `IsolationSession` lifecycle with modes `Disabled`, `Remote`, `Containerized`, `ReadOnly`.

### `ThreatProtectionEngine`

Ingests IOC lists from `ThreatFeed` sources and produces `ThreatMatch` results.

### `UebaEngine`

Maintains `BehaviorBaseline` per subject and emits `BehaviorAnomaly` on deviation.

### `ContinuousRiskEngine`

Synthesizes `RiskScore` from UEBA, threat, DLP, and CASB contributions.

### `SecurityDataLake` / `SecurityQueryEngine`

In-memory event store with retention presets 30/90/180/365/custom days.

### `SiemIntegrationManager`

Registers exporters for Splunk, Sentinel, Elastic, OpenSearch, QRadar, and Syslog. Supports JSON, CEF, LEEF, and Syslog formats.

## Controller integration

Agents report `SseTelemetryPayload` and push `SseIncidentBundleDto` to WireSentinel-Controller.

## Crate dependency graph

```
sse-core ──┬── swg
           ├── casb
           ├── dlp
           ├── browser-isolation
           ├── threat-protection
           ├── ueba
           ├── risk-engine
           ├── datalake
           ├── siem
           └── sdk

controller (DTOs only)
```

## External dependencies

| Repository | Used by |
|------------|---------|
| `WireSentinel/shared-types` | DTOs (`phase16`), service events |

## Phases covered

| Phase | Crate(s) |
|-------|----------|
| 16-A | `sse-core` |
| 16-B | `swg` |
| 16-C | `casb` |
| 16-D | `dlp` |
| 16-E | `browser-isolation` |
| 16-F | `threat-protection` |
| 16-G | `ueba` |
| 16-H | `risk-engine` |
| 16-I | `datalake` |
| 16-J | `siem`, `sdk`, `controller` |
