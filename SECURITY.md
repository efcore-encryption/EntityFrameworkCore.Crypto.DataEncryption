# Security

This document describes the cryptographic design decisions worth knowing before deploying
**EntityFrameworkCore.Crypto.DataEncryption**, its known limitations, how dependency vulnerabilities
are tracked, and the record of the most recent internal security review.

It is not a substitute for your own threat model, an independent code review, or (for regulated or
high-value data) a third-party penetration test — it is the honest, specific version of "here's what
we checked and what we didn't."

## Cryptographic design

| Component | Algorithm | Notes |
|---|---|---|
| Primary field encryption | AES-256-GCM | AEAD; 96-bit random nonce and 128-bit authentication tag per value. Tampered or truncated ciphertext fails to decrypt rather than silently returning garbage. |
| Legacy field encryption | AES-256-CBC | `AesCryptoProvider`. **Decrypt-only in intent** — see "Known limitations" below. Not authenticated; do not use for new encryption. |
| Key rotation / migration | `MigrationCryptoProvider` | Bridges legacy CBC data to GCM with zero downtime: all writes go to GCM, reads try GCM first and fall back to the legacy provider only when the ciphertext is provably not a GCM envelope. |
| Cloud/HSM-backed keys | Envelope encryption via Azure Key Vault, AWS KMS, or HashiCorp Vault | Master key material never leaves the vault; a cached data key is refreshed on a cooldown so a vault outage can't be turned into a request-storm. |
| Searchable encryption | HMAC-SHA256 blind index | Enables equality lookups (`WHERE`, joins) on encrypted columns without decrypting server-side; case-sensitivity is read from the actual model annotation rather than assumed by the caller. |
| License validation | Ed25519/EC-DSA signature, verified fully offline | No phone-home; a forged or corrupted license fails closed. |

All cryptographic operations run in-process. The library never generates, stores, or transmits your
private keys or vault credentials on your behalf.

## Known limitations

- **`AesCryptoProvider` (legacy AES-CBC) is deliberately weak for new data.** It reuses a single
  caller-supplied IV across every value and provides no authentication tag, which is fine for its
  actual job — decrypting rows written before a migration to GCM — but would be a real weakness if
  used to encrypt anything new. Nothing in this codebase does that; if you construct it directly,
  only ever use it as the `legacy` argument to `MigrationCryptoProvider`.
- **The ML.NET PII text classifier is probabilistic, not a compliance guarantee.** `PiiTextClassifier`
  flags free-text values as likely `PersonName`/`Address`/`FreeTextPii` based on a trained model and a
  confidence threshold (default 0.7). It will miss things and occasionally flag non-PII. Use the
  deterministic detectors (Aadhaar/PAN/SSN/IBAN/card/wallet — checksum-validated, not probabilistic)
  as your primary control for regulated identifiers, and treat the ML classifier as a discovery aid
  on top of that, not the control itself.
- **Auto-encryption is a heuristic, not an audit.** `UseAutoEncryption`'s convention-based column
  discovery (property-name matching, PII scanning) is a strong default but can both over- and
  under-encrypt versus a human who actually knows the schema. Review its findings — the compliance
  report generator is meant to make that review fast — rather than treating a clean scan as proof.
- **Offline license validation trusts the machine's clock and embedded public key.** This is a
  standard trade-off for phone-home-free licensing; it is not designed to resist a determined,
  privileged attacker on the host machine.

## Dependency vulnerability scanning

`dotnet list package --vulnerable` only means something with live access to a vulnerability feed
(nuget.org's by default) — it cannot be meaningfully run offline. Two ready-to-use wrappers are
included:

- `scripts/check-vulnerable-packages.ps1` — run locally on Windows before cutting a release.
- `scripts/check-vulnerable-packages.sh` — the same check, wired into
  `.github/workflows/dependency-audit.yml` to run on every push/PR to `main` and weekly on a
  schedule (a dependency you haven't touched can still grow a new CVE overnight). This workflow only
  takes effect once the project is pushed to a GitHub repo.

Both exit non-zero and write `vulnerable-packages-report.json` when something is found.

## Reporting a vulnerability

If you find a security issue in this library, please report it privately rather than opening a
public issue. *(Add your preferred contact — e.g. a security@ mailbox or a private advisory link —
here.)*

## Audit history

### 2026-08-27 — Licensing hardening: recurring rate-limited warnings (Efcore-Encryption.com-inspired)

Follow-up to a direct question about license-key forgery: the signature scheme itself
(ECDSA P-256, verified fully offline against an embedded public key) is not practically
forgeable without the private key, and the private key is never committed anywhere in this
repository (`tools/LicenseKeyGen` generates it out-of-band and explicitly does not persist
it). The real bypass vector is not forgery — it's that a customer with the full C# source
can simply delete or stub out the license checks themselves. No amount of client-side code
closes that gap; it's a licensing-terms/legal question, not a cryptographic one.

What this change actually does is narrow, additive hardening of the *soft* enforcement path, not assumed from memory:

- **`LicenseGate.IsGrantedOrWarn` now logs a rate-limited warning on every denied check, not
  just the first one.** Previously an ungated feature call logged once per process and then
  went silent forever, which is easy to lose in log noise or miss entirely on a long-running
  host. It now re-logs (default: every 5 minutes per feature, configurable via
  `LicenseGate.WarningInterval`) for as long as the gap between the requested feature and the
  current tier persists, using a lock-free `ConcurrentDictionary` + compare-and-swap so
  concurrent callers can't spam the log or race past the interval. This mirrors Efcore-Encryption.com's
  documented "warning-level" features, which log a rate-limited warning rather than either
  silently degrading forever or throwing.
- **The existing two-tier design (`IsGrantedOrWarn` for graceful degradation vs. `Demand` for
  hard-fail APIs) is now explicitly documented as intentional**, citing Efcore-Encryption.com's own split
  between features that only warn and the small set for Efcore-Encryption.com) that throw — and, importantly, Efcore-Encryption.com only throws when a
  license *is present but insufficient*, never merely for the total absence of any license.
  This codebase's `Demand` follows the same rule.
- **`LicensePayload.Seats` is now documented, not enforced, and that's deliberate.** A
  per-process library has no reliable way to observe how many total seats/hosts are running
  across a customer's fleet — the same non-enforceability Efcore-Encryption.com documents for its own
  comparable per-host session limits ("not technically enforced," not synchronized across
  scaled-out nodes). Rather than ship a fake enforcement mechanism, the XML docs on `Seats`
  now say plainly that it's informational.
- **Deliberately left unchanged:** the existing `LicenseEnforcementMode`
  (`Auto`/`Strict`/`WarnOnly`) startup fail-fast behavior in `LicenseEnforcer.Enforce()` —
  which can block host startup entirely when unlicensed in a detected-production
  environment — was not touched. That's a legitimate, separate design decision, and
  weakening it wasn't asked for; changing default startup-blocking behavior silently would be
  a bigger and riskier change than a logging cadence fix.

New tests (`LicensingTests` in `CryptoAndLicensingTests.cs`, 4 added): first-denial logs
immediately; repeat denials within the interval are suppressed to a single log line (asserted
across 50 simulated calls using an injectable `TimeProvider`, no real sleep); a warning fires
again once the interval elapses; and two different denied features are tracked and rate-limited
independently of each other. Full suite: 312/312 passing after this change (up from 308/308 at
the prior audit entry — the 4 new tests here). Solution builds clean.

**Not covered by this change:** anything that stops a customer from editing the source to
remove the license check calls — as noted above, that isn't a problem code inside the library
can solve. If license-terms enforcement against source tampering matters for your business
model, that's a legal/contractual question (license agreement terms, obfuscation, or a
compiled-only distribution model), not something this change attempts.

### 2026-08-27 — Four new features: decryption audit trail, async provider interface, OpenTelemetry, startup health check

Implemented and tested four features identified as roadmap/coverage gaps in the audit above.

**Decryption audit trail** (`DecryptionAuditTrail`, `IDecryptionAuditSink`, `DecryptionAuditMaterializationInterceptor`) —
row-level "who decrypted what, when, from where" via an `IMaterializationInterceptor`, so it sees the
actual materialized entity (and therefore a real primary key), unlike a `ValueConverter`. Delivery is
a non-blocking bounded channel (`BoundedChannelFullMode.Wait`, so a full buffer is reported as a drop
rather than silently discarded) fanning out concurrently to every registered sink; a failing sink is
logged and does not affect the others or retry (unlike `AlertDispatcher`, sinks here are expected to
own their own delivery guarantees). Ships with a built-in `LoggerDecryptionAuditSink`; forwarding to
Kafka/Elasticsearch/Splunk/Event Hubs is a few lines against the public `IDecryptionAuditSink`
interface, not built in. Gated behind the Enterprise tier.

**Async provider interface** (`IEncryptionCryptoProvider.EncryptAsync`/`DecryptAsync`) — added as
default interface methods so every existing implementation keeps compiling and behaving identically.
`KmsCryptoProvider` overrides them with a genuinely non-blocking refresh path, sharing one
`SemaphoreSlim` between its sync and async refresh code (a plain `lock` cannot be held across
`await`, and two separate locks would let a sync and an async refresh race on the same cached key
ring). EF Core's own `ValueConverter` pipeline has no async conversion hook, so `SaveChanges`/query
materialization stay synchronous regardless of this change — these methods are for direct,
out-of-pipeline callers and the KMS refresh path, documented as such in the interface's XML docs.

**OpenTelemetry observability** (`CryptoTelemetry`, `.EnableTelemetry()` extension methods) —
`System.Diagnostics.Metrics` counters/gauges reading existing `Interlocked` counters on
`AlertDispatcher`, `MigrationCryptoProvider`, `KmsCryptoProvider`, and the Sentinel
`ICryptoOperationMonitor` (so instruments are only polled when something actually collects, no added
hot-path cost), plus an `ActivitySource` span around KMS key-ring refreshes specifically (not around
every Encrypt/Decrypt call, again to avoid adding tracing overhead to a hot path this library doesn't
control). Idempotent via a `ConditionalWeakTable` guard, so calling `.EnableTelemetry()` twice on the
same instance never double-registers instruments.

**Startup health check** (`ICryptoHealthCheck`, `KmsReachabilityHealthCheck`,
`CryptoHealthCheckStartupService`, `CompositeCryptoHealthCheck`) — a dependency-free health-check
abstraction (Healthy/Degraded/Unhealthy) with a KMS reachability probe that reports Degraded (not
Unhealthy) when the KMS is reachable now but recent refreshes have been failing more often than
succeeding. Deliberately has no package dependency on
`Microsoft.Extensions.Diagnostics.HealthChecks` — the interface's XML docs include a ~15-line adapter
for apps that want to wire it into that standard ASP.NET Core abstraction.

**Verification**: 31 new tests added (async provider round-trips and KMS staleness/failure paths;
audit-trail publish/licensing/delivery-fan-out plus a full EF Core InMemory materialization
round-trip; OpenTelemetry counter/gauge/span emission and idempotency; health-check Healthy/Degraded/
Unhealthy/timeout scenarios and composite aggregation). One test-infrastructure bug was found and
fixed along the way — not a library bug: EF Core's InMemory provider gives two `DbContext` instances
configured with different services (here, a write context without the audit interceptor and a read
context with it) two different backing stores unless they share an explicit `InMemoryDatabaseRoot`,
which made the audit-trail interceptor tests briefly look like the row had vanished after a supposedly
successful `SaveChangesAsync`. Full test suite: 308/308 passing. Full solution build: clean. All 9
`DataEncryptionShowcase` scenarios re-verified end-to-end.

**Not covered by this change**: a demo scenario in `DataEncryptionShowcase` exercising the four new
features (the existing 9 scenarios were re-verified but none was added for these); built-in
SIEM/Kafka/Elasticsearch/Splunk sinks for the audit trail (the `IDecryptionAuditSink` extension point
is the deliverable, not a specific sink); a real dependency on
`Microsoft.Extensions.Diagnostics.HealthChecks` (by design, see above).

### 2026-08-27 — Internal source audit and remediation

A full review of the library's source (encryption providers, KMS/envelope key management, key
rotation, deterministic and ML-based PII detection, sensitive-data scanning, anomaly detection and
alerting, license validation, and EF Core model-builder wiring), followed by fixes for every
confirmed finding and new regression tests for the ones with real behavioral impact.

**Fixed — Critical**
- Stack-overflow denial-of-service in four deterministic PII detectors (Aadhaar, payment card, IBAN,
  bank account) on adversarially long input, via a `stackalloc` that wasn't being freed per loop
  iteration.
- `UseEncryption` could silently leave a column unencrypted if a third-party value converter was
  already registered on it; it now only treats its own converter as a safe no-op and throws otherwise.
- KMS providers (Azure Key Vault, HashiCorp Vault) could accept an empty/missing secret as a valid
  key instead of failing closed.
- `MigrationCryptoProvider` could, in rare cases, route genuine GCM ciphertext under a rotated-out
  key into the unauthenticated legacy CBC decryptor instead of surfacing the real "unknown key"
  error.

**Fixed — High**
- `SsnDetector` crashed on non-ASCII Unicode decimal digits.
- Convention-based auto-encryption could sweep up primary/foreign-key or unique-indexed columns,
  breaking joins and uniqueness; key-like columns are now excluded.
- A KMS key-size detection bug misclassified some valid 16/24-byte keys.
- `AlertDispatcher` delivered critical alerts sequentially, so one slow/hung channel could stall
  every other pending alert (and the digest flush) behind it; deliveries are now concurrent.

**Fixed — Medium/Low**
- KMS key refresh lacked thundering-herd protection and a post-failure cooldown, and silently
  accepted a misconfigured `KeyId == 0`.
- A per-call `HttpClient` allocation in two KMS providers was replaced with a shared instance.
- `AlertDispatcher`'s digest flush could merge unrelated alert groups that became due in the same
  tick into a single delivery, and `TryPublish` always reported success even for dropped alerts.
- `WhereBlindEquals` gained a model-aware overload that reads case-sensitivity from the actual
  annotation instead of trusting a caller-supplied flag.
- An out-of-range numeric license tier could crash later in the pipeline instead of being rejected
  up front.
- A narrow dispose-race window in `PiiTextClassifier` could build (and leak) a new ML engine on an
  already-disposed instance.
- Removed a dead, exact-duplicate source file (`PropertyBuilderExtensionsHelpers.cs`).

**Verification**: 10 new regression tests were added; for the highest-impact ones (the stack
overflows, the Unicode crash, and the two `AlertDispatcher` bugs) the test was first confirmed to
fail against the pre-fix code before being confirmed to pass against the fix. Full test suite: 277/277
passing. Full solution build: clean. All 9 scenarios of the `DataEncryptionShowcase` example app,
including the alert-pipeline scenario, verified end-to-end.

**Not covered by this audit**: dependency CVEs (see "Dependency vulnerability scanning" above —
run the script with network access), infrastructure/deployment hardening (secrets storage, network
policy, TLS configuration around wherever your KMS/Vault credentials live), and independent
third-party review.
