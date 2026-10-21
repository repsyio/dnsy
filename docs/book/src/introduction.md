# Introduction

![Nox, the DNSY mascot](../branding/mascot/nox-idle.svg)

DNSY is a single-binary DNS server written in Rust: UDP/TCP, DoT with mTLS, DoH with tokens, a caching and validating forwarder, authoritative JSON zones, DNSSEC signing, filtering, a query log with stats, a REST API and a web UI.

This book is the reference for operating and extending it.

## Where to start

- New here: [Install](install.md), then the [Quickstart](quickstart.md).
- Configuring: the [Configuration reference](configuration.md), [Zones](zones.md),
  [Resolver, upstreams and cache](resolver.md), [Filtering](filtering.md).
- Encrypted DNS: [DoT and mTLS](dot.md) and [DoH and tokens](doh.md).
- DNSSEC: the [concepts](dnssec.md) and the [operator guide](dnssec-operator-guide.md).
- Managing it: the [Web UI](web-ui.md), the [REST API](rest-api.md) and the [API reference](api-reference.md).
- Running it: [Operations](operations.md), [Logging and metrics](logging-and-metrics.md),
  [Backup and restore](backup-restore.md), [Upgrade](upgrade.md), [Troubleshooting](troubleshooting.md).
- Understanding it: [Architecture](architecture.md), [Security](security.md), [FAQ](faq.md),
  [Glossary](glossary.md).
- Contributing: [Contributing](contributing.md).
