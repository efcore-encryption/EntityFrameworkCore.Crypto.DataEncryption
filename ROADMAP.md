# EntityFrameworkCore.Crypto.DataEncryption — Product Roadmap

This document outlines the official product roadmap, upcoming releases, technical architectures, and target milestones for **`EntityFrameworkCore.Crypto.DataEncryption`** ([efcore-encryption.com](https://efcore-encryption.com/)).

---

## Roadmap Overview

```
 ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
 │    v11.0    │ ──> │    v11.1    │ ──> │    v11.2    │ ──> │    v11.3    │ ──> │    v11.6+   │
 ├─────────────┤     ├─────────────┤     ├─────────────┤     ├─────────────┤     ├─────────────┤
 │ ✅ Cloud KMS│     │ 🏢 Multi-   │     │ 🎭 Dynamic  │     │ 🔍 N-Gram   │     │ 🚀 CLI Tool │
 │    Azure/AWS│     │    Tenant   │     │    Data     │     │    Search   │     │             │
 │    Vault    │     │    Keys     │     │    Masking  │     │    Prefix   │     │             │
 │ ✅ Audit    │     │             │     │             │     │             │     │             │
 │    Trail    │     │             │     │             │     │             │     │             │
 │ ✅ OTel &   │     │             │     │             │     │             │     │             │
 │    Health   │     │             │     │             │     │             │     │             │
 └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

---

## ✅ Recently Shipped (v10.5.0 update — September 2026)

- **Expanded Rich Type & Column Encryption Support** — *shipped*. Full field-level encryption across `long`/`long?`, `decimal`/`decimal?` (with exact `"G29"` 29-digit precision), `double`/`double?` (with IEEE 754 `"R"` format), `Dictionary<string, string>`, arbitrary JSON/JSONB POCO classes, and Owned Entity Types (`.OwnsOne()` / `.OwnsMany()`).
- **Decryption Audit Trail** (`DecryptionAuditTrail`, `IDecryptionAuditSink`) — was v11.4, now shipped. Row-level "who decrypted what, when, from where" via an `IMaterializationInterceptor`, delivered through a non-blocking bounded channel. Ships with a built-in `LoggerDecryptionAuditSink`; Kafka/Elasticsearch/Splunk/Event Hubs sinks are not built-in but are a few lines against the public `IDecryptionAuditSink` interface. Enterprise tier.
- **Async Provider Interface** (`IEncryptionCryptoProvider.EncryptAsync`/`DecryptAsync`) — *not previously on this roadmap*. Default interface methods so every existing provider keeps compiling; `KmsCryptoProvider` overrides them with a genuinely non-blocking KMS refresh path. Note: EF Core's own `ValueConverter` pipeline has no async conversion hook, so `SaveChanges`/query materialization stay synchronous regardless — these methods are for direct/out-of-pipeline callers and KMS refresh, not an async query pipeline.
- **OpenTelemetry Observability** (`CryptoTelemetry`, `.EnableTelemetry()`) — *not previously on this roadmap*. `System.Diagnostics.Metrics` counters/gauges for `AlertDispatcher`, `MigrationCryptoProvider`, `KmsCryptoProvider`, and the Sentinel `ICryptoOperationMonitor`, plus an `ActivitySource` span around KMS key-ring refreshes. Metrics-only and refresh-only by design — no per-call Encrypt/Decrypt tracing, to avoid adding overhead to a hot path this library doesn't control.
- **Startup Health Check** (`ICryptoHealthCheck`, `KmsReachabilityHealthCheck`, `CryptoHealthCheckStartupService`) — *not previously on this roadmap*. Dependency-free health-check abstraction (Healthy/Degraded/Unhealthy) with a KMS reachability probe and an optional startup gate; ships without a hard dependency on `Microsoft.Extensions.Diagnostics.HealthChecks` — an XML-doc example shows the ~15-line adapter to the standard ASP.NET Core `IHealthCheck` interface for apps that already use it.

---

## Release Milestones & Feature Specifications

### 🎯 v11.1 — Multi-Tenant Cryptographic Key Isolation (`ITenantKeyProvider`)
*Target: Q3 2027* • **Tier: Enterprise**

#### Problem Statement
In multi-tenant SaaS applications sharing a single database schema, a compromised master key exposes data for all organizations.

#### Solution & Architecture
- **`ITenantKeyProvider`**: Dynamically derives or fetches distinct 256-bit AES-GCM keys per tenant ID.
- **Tenant Context Resolution**: Integrates with `IHttpContextAccessor`, claims, or async-local ambient tenant context.
- **Cryptographic Barrier**: Tenant A's key cannot decrypt Tenant B's data even if database records leak together in a raw backup.

```csharp
// Example API Preview:
builder.Services.AddMultiTenantEncryption<MyTenantKeyResolver>(options =>
{
    options.HeaderName = "X-Tenant-Id";
    options.FallbackPolicy = TenantKeyFallback.ThrowOnMissing;
    options.MasterKeyKmsIdentifier = "azure-kms-saas-root-key";
});
```

---

### 🎯 v11.2 — Role-Based Dynamic Data Masking (`IDataMaskingPolicy`)
*Target: Q4 2027* • **Tier: Enterprise**

#### Problem Statement
Certain employees (e.g. Tier-1 customer support or analytics workers) need to view partial data (e.g. `****-4321` or `j***@gmail.com`) without having permissions to decrypt the full unmasked PII.

#### Solution & Architecture
- **In-Memory Value Masking**: Intercepts EF Core materialization pipeline to apply customizable masking rules (Partial, Redact, Email, SSN, CreditCard) based on user roles (`ClaimsPrincipal`).
- **Zero Database Mutation**: Masking occurs purely in memory upon read; database storage remains 100% encrypted with full fidelity.

```csharp
// Example API Preview:
modelBuilder.Entity<Customer>()
    .Property(c => c.Ssn)
    .HasDynamicMasking(mask => mask
        .AllowRoles("ComplianceOfficer", "SecurityAdmin")
        .MaskAs("XXX-XX-{Last4}"));
```

---

### 🎯 v11.3 — Fuzzy, Range & Prefix Searchable Encryption (N-Gram Blind Indexing)
*Target: Q1 2028* • **Tier: Enterprise**

#### Problem Statement
Current blind indexing supports exact-match searches (`c.Email == "..."`), but real-world enterprise apps require `StartsWith()`, `Contains()`, or phone prefix searches.

#### Solution & Architecture
- **Tokenized Trigram / N-Gram Indexes**: Automatically breaks plaintext strings into overlapping 3-gram hashes stored in auxiliary shadow tables.
- **LINQ Provider Query Rewriting**: Intercepts `.Where(c => c.Phone.StartsWith("+1-555"))` and transforms the expression into fast HMAC shadow token lookups at the database engine level.

```csharp
// Example API Preview:
modelBuilder.Entity<Customer>()
    .Property(c => c.PhoneNumber)
    .HasPrefixSearchIndex(minPrefixLength: 3, maxPrefixLength: 6);
```

---

### ✅ v11.4 — Cryptographic Decryption Audit Trail (`IDecryptionAuditSink`) — SHIPPED
*Shipped: August 2026 (pulled forward from Q2 2027)* • **Tier: Enterprise**

#### Problem Statement
Regulatory compliance frameworks (HIPAA §164.312, GDPR Art. 30, DPDP Act 2023) mandate detailed records of processing activities and data access logs.

#### Solution & Architecture
- **Decryption Interceptor**: Hooks into EF Core materialization to log *who* accessed *which row*, *when*, *from what IP address*, and *under what authorization context*.
- **High-Throughput Async Channels**: Non-blocking `System.Threading.Channels` queue to push audit events to Kafka, Elasticsearch, Splunk, or Azure Event Hubs without degrading query latency.

```csharp
// Example API Preview:
builder.Services.AddDecryptionAuditTrail(options =>
{
    options.LogEntityPrimaryKey = true;
    options.IncludeUserClaims = new[] { "sub", "role", "ip_address" };
    options.UseKafkaSink(kafka => kafka.BootstrapServers = "kafka.corp.internal:9092");
});
```

---

### 🎯 v11.6 — Zero-Downtime CLI Migration Tool (`dotnet ef-crypto migrate`)
*Target: Q4 2028* • **Tier: Community & Enterprise**

#### Problem Statement
Existing applications with millions of unencrypted records face long downtime windows when applying initial encryption or migrating legacy AES-CBC data to AES-GCM.

#### Solution & Architecture
- **Global .NET CLI Tool**: `dotnet tool install -g efcore-crypto-cli`.
- **Chunked Background Migrations**: Reads batches of $N$ records (e.g. 1,000 rows), encrypts in parallel using SIMD/AES-NI, and updates in small transactional batches with zero table locking.
- **Live Progress & Checkpoints**: Resumable state file allowing pausing and resuming migrations seamlessly in production environments.

```bash
# Example CLI Command:
dotnet ef-crypto migrate \
  --connection-string "Server=db.prod;Database=AppDb;..." \
  --context AppDbContext \
  --batch-size 500 \
  --concurrency 8 \
  --dry-run false
```

---

### 🎯 v12.1 — Hardware Security Module (HSM) Native Driver (PKCS#11 & YubiHSM)
*Target: Q1 2029* • **Tier: Enterprise**

#### Problem Statement
Banking, defense, and sovereign cloud deployments require FIPS 140-2 Level 3 physical HSM key protection where keys never touch host RAM unencrypted.

#### Solution & Architecture
- **PKCS#11 C-Interop**: Native interop with Thales Luna, AWS CloudHSM, NitroKey HSM, and YubiKey HSM2.
- **Envelope Wrapping (AES-KW)**: Keys decrypted only inside hardware boundary.

---

## Feature Comparison Matrix by Tier

| Feature | Community | Enterprise ($2,999/yr or $5,999/5-yr) |
|---|:---:|:---:|
| **Field Encryption (AES-GCM / AES-CBC)** | ✅ | ✅ |
| **Cloud KMS (Azure Key Vault, AWS KMS, HashiCorp)** | ✅ | ✅ |
| **Key Rotation & Zero-Downtime Migration Bridge** | ✅ | ✅ |
| **Searchable Exact-Match Blind Indexing** | ✅ | ✅ |
| **Convention Auto-Encryption (`UseAutoEncryption`)** | ✅ | ✅ |
| **Deterministic PII Scanning (Aadhaar, SSN, IBAN, PAN)** | ✅ | ✅ |
| **ML-Powered PII Text Classification** | ❌ | ✅ |
| **Crypto Sentinel Anomaly Detection & Telemetry** | ❌ | ✅ |
| **Multi-Channel Alert Pipeline (SMTP & Webhook)** | ❌ | ✅ |
| **DPDP & GDPR Compliance Evidence Packs** | ❌ | ✅ |
| **v11.1: Multi-Tenant Key Isolation (`ITenantKeyProvider`)** | ❌ | ✅ |
| **v11.2: Role-Based Dynamic Data Masking** | ❌ | ✅ |
| **v11.3: Fuzzy & Prefix Searchable Encryption** | ❌ | ✅ |
| **✅ Decryption Audit Trail & SIEM Sink Extension Point (shipped)** | ❌ | ✅ |
| **✅ Async Provider Interface (`EncryptAsync`/`DecryptAsync`, shipped)** | ✅ | ✅ |
| **✅ OpenTelemetry Metrics & KMS Refresh Tracing (shipped)** | ✅ | ✅ |
| **✅ Startup Health Check (`ICryptoHealthCheck`, shipped)** | ✅ | ✅ |
| **v11.6: Zero-Downtime CLI Migration Tool** | ✅ (Basic) | ✅ |
| **v12.1: Hardware Security Module (PKCS#11 / HSM)** | ❌ | ✅ |

---

## Feedback & Community Voting

To request features or vote on roadmap prioritization:
- **Website**: [https://efcore-encryption.com/](https://efcore-encryption.com/)
- **License Inquiries**: [https://efcore-encryption.com/#plans](https://efcore-encryption.com/#plans)
- **GitHub Discussions**: [GitHub Issues & Feature Requests](https://github.com/RoyceLark/EntityFrameworkCore.Crypto.DataEncryption/issues)
