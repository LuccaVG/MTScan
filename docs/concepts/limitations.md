# Limitations

MTScan `1.0.0-alpha` has intentionally narrow boundaries.

## Vulnerability coverage depends on Nuclei

MTScan does not contain an independent CVE database or exploit engine. CVE detection depends on Nuclei templates, their metadata, enabled filters, the target's observable behavior, and scanner compatibility.

A missing CVE finding is not proof of safety. A CVE finding is not proof of successful exploitation.

## Chained vulnerability stage is HTTP-focused

Naabu can discover arbitrary TCP services, but the chained Nuclei stage receives HTTP(S) URLs confirmed by HTTPX. Non-HTTP vulnerability assessment is outside the current chained vulnerability stage.

## Report parsing is lossy by design

The high-level report normalizes scanner output and may omit raw protocol evidence. Use explicit upstream exports or stored responses when an engagement requires raw evidence retention.

## No stable JSON report contract yet

`--json-output` improves scanner parsing. It does not define a durable MTScan JSON report schema in the alpha release.

## Local web API is alpha

API payload fields, profiles, storage representation, and schedule behavior may change before stable `1.0.0`. It is intended for the bundled local dashboard, not as a hardened Internet-facing service.

## Storage fallback is not a distributed database replacement

The JSONL/file backend is a local fallback. It does not provide Cassandra's concurrency or operational characteristics and is not intended for multi-node shared use.

## Scanner compatibility varies by upstream version

MTScan validates common ProjectDiscovery flags and binary behavior, but upstream CLI changes can affect command compatibility. Pin scanner versions for reproducible engagements.

## Installer is invasive

The full installer runs with elevated privileges, installs packages, may modify system configuration, configures Go, and may install/start Cassandra. Use a dedicated security VM when possible.

## Testing is not product certification

Loopback fixtures, safe Nuclei templates, scanner stubs, and real-tool local compatibility tests validate MTScan behavior but do not certify compatibility with Metasploitable, a particular enterprise product, every Linux distribution, or every CVE template.
