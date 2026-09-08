# EntityFrameworkCore.Crypto.DataEncryption

[![NuGet Version](https://img.shields.io/nuget/v/EntityFrameworkCore.Crypto.DataEncryption.svg?style=flat-square&color=blue)](https://www.nuget.org/packages/EntityFrameworkCore.Crypto.DataEncryption)
[![NuGet Downloads](https://img.shields.io/nuget/dt/EntityFrameworkCore.Crypto.DataEncryption.svg?style=flat-square&color=blue)](https://www.nuget.org/packages/EntityFrameworkCore.Crypto.DataEncryption)
[![.NET](https://img.shields.io/badge/.NET-9.0%20%7C%2010.0-512bd4.svg?style=flat-square)](https://dotnet.microsoft.com/)
[![License: Commercial / Community](https://img.shields.io/badge/License-Commercial%20%7C%20Community-purple.svg?style=flat-square)](https://efcore-encryption.com/#plans)
[![Cryptography: AES--256--GCM AEAD](https://img.shields.io/badge/Crypto-AES--256--GCM%20AEAD-green.svg?style=flat-square)](SECURITY.md)
[![In-Process](https://img.shields.io/badge/Execution-100%25%20In--Process-success.svg?style=flat-square)](SECURITY.md)

> **Official Links**: [Website & Licensing](https://efcore-encryption.com/) • [The Complete Guide](docs/COMPLETE_GUIDE.md) • [Product Roadmap](ROADMAP.md) • [Security & Threat Model](SECURITY.md)

---

## Overview

**EntityFrameworkCore.Crypto.DataEncryption** provides enterprise-grade, transparent field-level data encryption for Entity Framework Core (EF Core 9 and 10). 

It combines authenticated AEAD cryptographic engines (AES-256-GCM with random nonces), native Cloud KMS integrations (Azure Key Vault, AWS KMS, HashiCorp Vault), fast searchable encryption (HMAC-SHA256 blind indexing), convention-based auto-encryption, automated PII discovery, real-time decryption anomaly detection (Crypto Sentinel), and one-click compliance evidence generation (India DPDP Act 2023 §8, GDPR Art. 32, PCI-DSS).

### Why Field-Level Encryption?
- **Zero-Knowledge Storage**: Data is encrypted *before* it leaves your application process. The database server, storage engine, replication streams, database administrators, and disk backups see **only encrypted ciphertext**.
- **Transparent Execution**: EF Core transparently encrypts data on write (`SaveChanges`) and decrypts data on materialization (`SELECT`), keeping your domain logic, repositories, and business services clean.
- **100% In-Process & Private**: All cryptographic operations execute entirely in your application process memory. Your private keys and master secrets are never sent to external servers, third-party clouds, or telemetry channels.

## Disclaimer

<h4 align="center">:warning: This package is maintained by efcore-encryption.com and is not affiliated with Microsoft. :warning:</h4><br>

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Supported Data Types & Column Shapes](#supported-data-types--column-shapes)
- [Quick Start Guide](#quick-start-guide)
- [Core Capabilities](#core-capabilities)
  - [1. Cryptographic Providers, AEAD & Key Rotation](#1-cryptographic-providers-aead--key-rotation)
  - [2. Cloud Key Management (Azure Key Vault, AWS KMS, HashiCorp Vault)](#2-cloud-key-management-azure-key-vault-aws-kms-hashicorp-vault)
  - [3. Searchable Encryption (Blind Indexing)](#3-searchable-encryption-blind-indexing)
  - [4. Convention-Based Auto-Encryption (`UseAutoEncryption`)](#4-convention-based-auto-encryption-useautoencryption)
  - [5. Zero-Downtime Legacy Migration (AES-CBC to AES-GCM)](#5-zero-downtime-legacy-migration-aes-cbc-to-aes-gcm)
  - [6. Automated PII Scanning & ML.NET Classification](#6-automated-pii-scanning--mlnet-classification)
  - [7. Crypto Sentinel: Anomaly Detection & Multi-Channel Alerting](#7-crypto-sentinel-anomaly-detection--multi-channel-alerting)
  - [8. Decryption Audit Trail & OpenTelemetry Observability](#8-decryption-audit-trail--opentelemetry-observability)
  - [9. Compliance Evidence Reporting (DPDP 2023 & GDPR Art. 32)](#9-compliance-evidence-reporting-dpdp-2023--gdpr-art-32)
- [Sample Projects & Runnable Demos](#sample-projects--runnable-demos)
- [Enterprise Roadmap](#enterprise-roadmap)
- [Plan Tiers & Licensing](#plan-tiers--licensing)
- [Security & Cryptographic Architecture](#security--cryptographic-architecture)
- [Enterprise Support](#enterprise--commercial-support)

---

## Key Features

- 🔒 **Authenticated Field Encryption (AES-256-GCM AEAD)**: Industry-standard 256-bit AES-GCM Authenticated Encryption with Associated Data. Each encrypted property write automatically receives a unique 96-bit cryptographically secure random nonce and a 128-bit authentication tag, guaranteeing confidentiality and tamper resistance.
- ☁️ **Enterprise Cloud KMS & Secret Vaults**: Direct envelope encryption and credential caching integrations for **Azure Key Vault**, **AWS KMS**, and **HashiCorp Vault**, providing configurable in-memory token/DEK caching for sub-millisecond query execution without remote roundtrip overhead.
- 🔍 **Searchable Encryption (Blind Indexing)**: Keyed HMAC-SHA256 deterministic shadow indexing enabling native database index seeks (`WHERE` equality filters and SQL joins) directly on indexed columns without client-side decryption or plaintext exposure.
- 🛡️ **Convention-Based Auto-Encryption (`UseAutoEncryption`)**: Secure-by-default architecture that automatically scans entity models and encrypts sensitive PII columns (SSN, Passport, National ID, Bank Accounts, Salary, Credit Cards) by naming conventions with explicit opt-out annotations (`[DoNotEncrypt]`, `[ScanExempt]`).
- 📊 **Comprehensive Data Type & Shape Support**: Transparent encryption support for `string`, `byte[]`, numeric integers & floating points (`long`, `decimal` with exact `"G29"` 29-digit precision, `double` with IEEE 754 `"R"` format), `Dictionary<string, string>`, arbitrary JSON/JSONB POCO classes, and EF Core Owned Entity Types (`.OwnsOne()` / `.OwnsMany()`).
- 🔄 **Zero-Downtime Key Rotation & Multi-Key Rings**: Seamlessly rotate encryption keys with versioned key IDs (`keyId`) — writes always use the active primary key, while historical records transparently decrypt using the matching key from the key ring.
- 🌉 **Legacy Migration Bridge (`MigrationCryptoProvider`)**: Dual-format compatibility provider enabling non-blocking, zero-downtime database upgrades from legacy AES-CBC systems to modern authenticated AES-GCM envelopes.
- 🤖 **Automated PII Scanning & ML.NET Classification**: In-depth sensitive data discovery across EF Core models and live sampled database rows, combining checksum-verified deterministic detectors (Aadhaar Verhoeff, Credit Card Luhn, IBAN mod-97, PAN, US SSN, Crypto Wallets) with ML.NET text classification models.
- 🚨 **Crypto Sentinel Real-Time Anomaly Detection**: Singular Spectrum Analysis (SSA) time-series anomaly detection engine learning baseline application decryption rates to detect and alert on bulk data scraping or exfiltration spikes within seconds.
- 📬 **Multi-Channel Alert Pipeline**: Enterprise alert dispatcher featuring instant critical event triggers, 15-minute batched digest windows, retries, dead-letter storage, `ILogger`, SMTP email notifications via MailKit, and HMAC-SHA256 signed Webhooks for SIEM / SOC integrations.
- 📜 **Audit-Ready Compliance Evidence Packs**: Single-method generation of audit evidence packs in structured JSON and print-ready A4 HTML formats mapped to **India DPDP Act 2023 §8**, **GDPR Art. 32**, and **PCI-DSS**.
- 🕵️ **Decryption Audit Trail Logging**: Fine-grained row-level materialization audit interceptor (`IDecryptionAuditSink`) logging "who decrypted which record, when, from which IP address" through non-blocking bounded channels.
- ⚡ **Async Provider Interface**: Native `EncryptAsync` and `DecryptAsync` methods on `IEncryptionCryptoProvider` with non-blocking KMS credential refresh for out-of-pipeline callers.
- 🔭 **OpenTelemetry Observability**: Built-in `System.Diagnostics.Metrics` counters and gauges for alert dispatches, migration progress, KMS cache hits, and Sentinel telemetry, plus `ActivitySource` tracing around KMS key refreshes.
- 🩺 **Startup Health Checks**: Dependency-free `ICryptoHealthCheck` abstraction with active KMS reachability probes (Healthy / Degraded / Unhealthy) and optional startup gating.

---

## Architecture

```
┌──────────────────────────────── Application Process ────────────────────────────────┐
│                                                                                     │
│  EF Core Query / SaveChanges                                                        │
│       │                                                                             │
│       ▼                                                                             │
│  Value Converters ────────► IEncryptionCryptoProvider (In-Process AES-256-GCM)      │
│       │                         ├─ AesGcmCryptoProvider (Random Nonce + Tag)        │
│       │                         ├─ KmsCryptoProvider    (Azure / AWS / Vault Cache) │
│       │                         └─ MigrationCryptoProvider (CBC → GCM Bridge)       │
│       │                                                                             │
│       ├───────────────────► BlindIndexInterceptor ────► Keyed HMAC-SHA256 Index     │
│       │                                                                             │
│       ├───────────────────► DecryptionAuditTrail  ────► Bounded Channel Audit Sink  │
│       │                                                                             │
│       └─ Telemetry Interceptor ─► CryptoOperationMonitor ─► Anomaly Detector (SSA)  │
│                                                                 │                   │
│  SensitiveDataScanner (Deterministic + ML.NET)                  ▼                   │
│       │                                                  AlertDispatcher            │
│       ▼                                            ┌────────────┼────────────┐      │
│  ComplianceReportGenerator                         ▼            ▼            ▼      │
│  (JSON / HTML Evidence Pack)                    ILogger       SMTP        Webhook   │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
               Database sees Ciphertext + Shadow Hashes Only
```

---

## Installation

Install the package via NuGet Package Manager or .NET CLI:

### .NET CLI
```bash
dotnet add package EntityFrameworkCore.Crypto.DataEncryption
```

### Package Manager Console
```powershell
PM> Install-Package EntityFrameworkCore.Crypto.DataEncryption
```

### PackageReference
```xml
<PackageReference Include="EntityFrameworkCore.Crypto.DataEncryption" Version="10.5.0" />
```

---

## Supported Data Types & Column Shapes

EntityFrameworkCore.Crypto.DataEncryption provides comprehensive field-level encryption across primitive, numeric, structured, and EF Core complex navigation types:

| Property Type | Default Storage Format | Supported Storage Formats | Database Column Type | Cryptographic & Serialization Details |
|---|---|---|---|---|
| `string` | Base64 String | `Base64`, `Binary` | `TEXT` / `VARCHAR` / `BLOB` | UTF-8 encoded plaintext encrypted into ciphertext envelope. |
| `byte[]` | Binary | `Binary`, `Base64` | `BLOB` / `VARBINARY` / `TEXT` | Raw binary ciphertext representation for documents/blobs. |
| `long`, `long?` | Base64 String | `Base64`, `Default` | `TEXT` / `VARCHAR` | Invariant culture string serialization with exact integer roundtrips. |
| `decimal`, `decimal?` | Base64 String | `Base64`, `Default` | `TEXT` / `VARCHAR` | Invariant `"G29"` format preserving up to 29 digits of exact precision. |
| `double`, `double?` | Base64 String | `Base64`, `Default` | `TEXT` / `VARCHAR` | Invariant `"R"` IEEE 754 format preserving `NaN`, `+Infinity`, `-Infinity`. |
| `Dictionary<string, string>` | Base64 String | `Base64`, `Default` | `TEXT` / `VARCHAR` | High-performance JSON serialization via `System.Text.Json`. |
| JSON / JSONB POCO Classes | Base64 String | `Base64`, `Default` | `TEXT` / `VARCHAR` | Any concrete class or record serialized to JSON and encrypted. |
| Owned Entity Types | Inherited | Matches property | Table column (owned/split) | Properties inside `.OwnsOne()` / `.OwnsMany()` are walked and encrypted. |

> **Column Type Mapping Note**: For numeric, dictionary, and JSON types, EF Core maps the property to a text-compatible database column (e.g. `[Column(TypeName = "TEXT")]` in SQLite/PostgreSQL or `nvarchar(max)` in SQL Server), since the encrypted payload is stored as an authenticated Base64 string.

---

## Quick Start Guide

### 1. Define Your Sensitive Entity Model

Decorate sensitive properties with `[CryptoEncrypted]` or configure them via the Fluent API in `OnModelCreating`:

```csharp
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore.DataEncryption;

public class Customer
{
    public int Id { get; set; }

    public string FullName { get; set; } = string.Empty;

    // Encrypted string (Base64 text)
    [CryptoEncrypted]
    public string Ssn { get; set; } = string.Empty;

    // Searchable encrypted column (AES-GCM + HMAC-SHA256 blind index)
    [CryptoEncrypted]
    public string Email { get; set; } = string.Empty;

    // Raw binary encrypted document
    [CryptoEncrypted(CryptoStorageFormat.Binary)]
    public byte[]? IdentityDocumentScan { get; set; }

    // Numeric encryption (stored as encrypted Base64 text)
    [CryptoEncrypted]
    [Column(TypeName = "TEXT")]
    public decimal AnnualSalary { get; set; }

    [CryptoEncrypted]
    [Column(TypeName = "TEXT")]
    public long? AccountNumber { get; set; }

    // Encrypted Dictionary metadata
    [CryptoEncrypted]
    [Column(TypeName = "TEXT")]
    public Dictionary<string, string>? Metadata { get; set; }

    // Encrypted JSON POCO preferences
    [CryptoEncrypted]
    [Column(TypeName = "TEXT")]
    public CustomerPreferences? Preferences { get; set; }

    // Owned Entity Type navigation
    public Address HomeAddress { get; set; } = new Address();
}

// Owned entity type
public class Address
{
    [CryptoEncrypted]
    public string Street { get; set; } = string.Empty; // Encrypted inside owned entity

    public string City { get; set; } = string.Empty;   // Plaintext
}

public class CustomerPreferences
{
    public string Theme { get; set; } = "dark";
    public bool ReceiveNewsletter { get; set; }
}
```

### 2. Configure Your `DbContext`

Instantiate your cryptographic provider and call `modelBuilder.UseEncryption(...)` as the final step in `OnModelCreating`:

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.DataEncryption;
using Microsoft.EntityFrameworkCore.DataEncryption.Providers;

public class AppDbContext : DbContext
{
    private readonly IEncryptionCryptoProvider _provider;

    public DbSet<Customer> Customers => Set<Customer>();

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
        // 256-bit AES-GCM AEAD provider
        byte[] primaryKey = LoadKeyFromSecureStore(); // 32-byte key
        _provider = new AesGcmCryptoProvider(primaryKey);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure owned entity navigation
        modelBuilder.Entity<Customer>().OwnsOne(c => c.HomeAddress);

        // Activate encryption converters across all marked properties
        modelBuilder.UseEncryption(_provider);
    }
}
```

---

## Core Capabilities

### 1. Cryptographic Providers, AEAD & Key Rotation

#### AES-256-GCM AEAD Provider (Recommended)
`AesGcmCryptoProvider` implements Authenticated Encryption with Associated Data (AEAD). Every encrypted value is stored with a binary or Base64 envelope:
`[version: 1 byte][keyId: 1 byte][nonce: 12 bytes][tag: 16 bytes][ciphertext: N bytes]`

```csharp
// Generate a cryptographically secure 256-bit master key
byte[] key = AesGcmCryptoProvider.GenerateKey();
var provider = new AesGcmCryptoProvider(key);
```

#### Multi-Key Ring for Zero-Downtime Key Rotation
When rotating keys, pass the new active key as `primaryKey` and historical keys in `decryptionKeys`. New writes are automatically encrypted with the latest key, while existing records transparently decrypt using the matching historical key indicated by the envelope `keyId`:

```csharp
var keyRingProvider = new AesGcmCryptoProvider(
    primaryKey: new AesGcmKey(keyId: 2, new256BitKey),           // Used for all new writes
    decryptionKeys: new[] { 
        new AesGcmKey(keyId: 1, historical256BitKey)              // Used for seamless historical reads
    }
);
```

---

### 2. Cloud Key Management (Azure Key Vault, AWS KMS, HashiCorp Vault)

Eliminate local raw key storage. Connect directly to enterprise Cloud KMS & Secret Vaults with built-in in-memory caching for zero query latency:

```csharp
// Program.cs - Azure Key Vault
builder.Services.AddAzureKeyVaultEncryption(
    azure =>
    {
        azure.VaultUri = "https://corp-production-vault.vault.azure.net/";
        azure.AccessTokenProvider = async ct => await GetManagedIdentityTokenAsync(ct);
    },
    keyOptions =>
    {
        keyOptions.PrimaryKeyIdentifier = "database-master-key";
        keyOptions.CacheTtl = TimeSpan.FromHours(24); // Microsecond in-memory throughput
        keyOptions.HistoricalKeys.Add(new KmsKeyReference(1, "database-master-key-v1"));
    }
);

// Program.cs - AWS KMS
builder.Services.AddAwsKmsEncryption(
    aws =>
    {
        aws.Region = "us-east-1";
        aws.CustomKeyFetcher = async (keyArn, ver, ct) => await FetchKeyFromAwsKmsAsync(keyArn, ct);
    },
    keyOptions =>
    {
        keyOptions.PrimaryKeyIdentifier = "arn:aws:kms:us-east-1:123456789012:key/my-dek";
    }
);

// Program.cs - HashiCorp Vault
builder.Services.AddHashiCorpVaultEncryption(
    vault =>
    {
        vault.VaultAddress = "https://vault.corp.internal:8200";
        vault.TokenProvider = async ct => await GetAppRoleTokenAsync(ct);
    },
    keyOptions =>
    {
        keyOptions.PrimaryKeyIdentifier = "finance/database-encryption";
    }
);
```

---

### 3. Searchable Encryption (Blind Indexing)

Because AES-GCM produces randomized nonces on every write, direct SQL `WHERE` queries cannot match ciphertext. **Blind Indexing** creates an indexed deterministic HMAC-SHA256 shadow column:

```csharp
// 1. Model Configuration in OnModelCreating
modelBuilder.Entity<Customer>()
    .Property(c => c.Email)
    .HasBlindIndex(caseInsensitive: true); // Generates EmailBlindIndex shadow column + DB Index

// 2. Interceptor Registration in DbContext Options
var blindIndexKey = LoadDedicatedHmacKey();
var hasher = new BlindIndexHasher(blindIndexKey);
optionsBuilder.AddInterceptors(new BlindIndexInterceptor(hasher));

// 3. Fast Index-Seek Query (executes at DB index without client-side decryption)
var customer = await context.Customers
    .WhereBlindEquals(nameof(Customer.Email), "alice.johnson@example.com", hasher)
    .FirstOrDefaultAsync();
```

---

### 4. Convention-Based Auto-Encryption (`UseAutoEncryption`)

Secure-by-default architecture that automatically scans entity models and encrypts sensitive PII columns (SSN, Passport, National ID, Bank Accounts, Salary, Credit Cards) by naming conventions:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    base.OnModelCreating(modelBuilder);

    // Automatically discovers and encrypts PII fields by convention
    modelBuilder.UseAutoEncryption(_provider);
}
```

#### Opting Out or Formally Exempting Fields
```csharp
public class UserAccount
{
    public int Id { get; set; }

    // Explicit opt-out with recorded justification for compliance audits
    [DoNotEncrypt(Reason = "Filtered frequently in server-side LIKE queries")]
    public string SupportSearchNotes { get; set; }

    // Formally accepted risk signed off by Security/DPO
    [ScanExempt("Public searchable alias requirement", ApprovedBy = "Security Officer")]
    public string PublicAlias { get; set; }
}
```

---

### 5. Zero-Downtime Legacy Migration (AES-CBC to AES-GCM)

Migrate legacy AES-CBC databases to authenticated AES-GCM envelopes with zero downtime. `MigrationCryptoProvider` reads both CBC and GCM formats, while directing all new writes into modern AES-GCM:

```csharp
var legacyCbc = new AesCryptoProvider(cbcKey, cbcIv);
var modernGcm = new AesGcmCryptoProvider(gcmKey);

// Reads both CBC and GCM formats; writes only modern AES-GCM
var bridgeProvider = new MigrationCryptoProvider(modernGcm, legacyCbc);

modelBuilder.UseEncryption(bridgeProvider);
```

---

### 6. Automated PII Scanning & ML.NET Classification

Run automated PII scanning across your EF Core entity models and live sampled database data to discover unencrypted sensitive data:

```csharp
// Run on-demand scan
var scanner = serviceProvider.GetRequiredService<SensitiveDataScanner>();
ScanReport report = await scanner.ScanAsync(dbContext);

foreach (var finding in report.Findings)
{
    Console.WriteLine($"[{finding.Severity}] {finding.EntityType}.{finding.Property} -> {finding.Kind} (Confidence: {finding.Confidence:P0})");
}

// Or run automatically once on application startup
builder.Services.AddStartupSensitiveDataScan<AppDbContext>();
```

---

### 7. Crypto Sentinel: Anomaly Detection & Multi-Channel Alerting

Real-time Singular Spectrum Analysis (SSA) time-series monitoring of application decryption activity. It learns baseline application behavior and flags exfiltration-shaped spikes in seconds:

```csharp
// Program.cs
builder.Services.AddDataEncryptionML(options =>
{
    options.LicenseKey = builder.Configuration["EfCrypto:LicenseKey"];

    // Sentinel configuration
    options.Sentinel.SamplingInterval = TimeSpan.FromSeconds(1);
    options.Sentinel.TrainingWindow = 120;
    options.Sentinel.MinEventsForAlert = 50;
    options.Sentinel.CriticalEventsThreshold = 500;

    // Multi-channel alerting
    options.Email = new SmtpEmailOptions
    {
        Host = "smtp.corp.internal",
        Port = 587,
        Username = "security@corp.internal",
        Password = builder.Configuration["Smtp:Password"],
        From = "security@corp.internal",
        To = { "soc@corp.internal", "dpo@corp.internal" }
    };

    options.Webhook = new WebhookOptions
    {
        Url = "https://siem.corp.internal/api/v1/security-alerts",
        Secret = builder.Configuration["Webhook:Secret"]
    };
});

builder.Services.AddDbContext<AppDbContext>((sp, options) =>
{
    options.UseSqlServer(connectionString)
           .UseCryptoSentinel(sp);
});
```

---

### 8. Decryption Audit Trail & OpenTelemetry Observability

Log row-level materialization audits ("who decrypted what, when, from which IP") and export real-time OpenTelemetry metrics:

```csharp
// Decryption audit trail (Enterprise tier)
builder.Services.AddDataEncryptionML(options =>
{
    options.LicenseKey = licenseKey;
    options.AuditTrail.LogEntityPrimaryKey = true;
});
builder.Services.AddDecryptionAuditSink<MyKafkaAuditSink>();

services.AddDbContext<AppDbContext>((sp, o) => o
    .UseSqlServer(connectionString)
    .UseDecryptionAuditTrail(sp));

// Set ambient user context per request
app.Use(async (ctx, next) =>
{
    DecryptionAuditContext.Current = new DecryptionAuditContext
    {
        UserId = ctx.User.FindFirst("sub")?.Value,
        IpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
    };
    await next();
});

// Async provider calls (for direct out-of-pipeline callers)
byte[] ciphertext = await kmsCryptoProvider.EncryptAsync(plaintext);

// OpenTelemetry metrics and tracing
builder.Services.AddCryptoTelemetry();
builder.Services.AddCryptoHealthChecks(o => o.FailFastOnUnhealthy = false);
builder.Services.AddKmsHealthCheck();
```

---

### 9. Compliance Evidence Reporting (DPDP 2023 & GDPR Art. 32)

Generate executive compliance evidence packs with complete inventory, coverage stats, accepted risks, and alert history:

```csharp
var generator = serviceProvider.GetRequiredService<ComplianceReportGenerator>();

ComplianceReport report = generator.Generate(
    dbContext,
    encryptionAlgorithmDescription: "AES-256-GCM authenticated envelope with random 96-bit nonce",
    scanReport: scanReport,
    recentAlerts: alertDispatcher.GetRecentAlerts()
);

// Export JSON evidence pack or print-ready A4 HTML certificate
File.WriteAllText("compliance-evidence.json", generator.ToJson(report));
File.WriteAllText("compliance-evidence.html", generator.ToHtml(report));
```

---

## Sample Projects & Runnable Demos

The repository includes three complete, runnable sample applications:

| Sample Project | Type | Description |
|---|---|---|
| **[CryptoAesSample](Example/CryptoAesSample)** | Console App | Standalone console app demonstrating encryption of strings, binary byte arrays, numeric types (`long`, `decimal`), `Dictionary<string, string>`, and owned entity types. |
| **[DataEncryptionShowcase](Example/DataEncryptionShowcase)** | Console Showcase | 9 in-depth executable enterprise scenarios: raw SQL inspection, key rotation, convention auto-encryption, blind-index search, ML PII scanning, DPDP compliance reporting, Sentinel anomaly detection, multi-channel alerts, and cloud KMS integration. |
| **[DataEncryptionWebApi](Example/DataEncryptionWebApi)** | ASP.NET Core Web API | Production-ready Web API with Swagger UI, SQLite persistence, REST endpoints for encrypted customer entities, Sentinel anomaly detection middleware, and startup health checks. |

### Running the Samples

```bash
# 1. Basic Aes Crypto Sample:
dotnet run --project Example/CryptoAesSample/AesCryptoSample.csproj

# 2. Multi-Scenario Enterprise Showcase:
dotnet run --project Example/DataEncryptionShowcase/DataEncryptionShowcase.csproj

# 3. Web API with Swagger UI:
dotnet run --project Example/DataEncryptionWebApi/DataEncryptionWebApi.csproj
```

---

## Enterprise Roadmap & Upcoming Releases

We are continuously developing cutting-edge enterprise data security extensions for EF Core. Upcoming features scheduled for subsequent releases:

✅ **Shipped ahead of schedule (v10.5.0 update — August 2026)**: Decryption Audit Trail Logging (was v11.4), Expanded Rich Type & Column Encryption (`long`, `decimal`, `double`, `Dictionary`, JSON, Owned types), Async Provider Interface, OpenTelemetry Observability, and Startup Health Checks. See [ROADMAP.md](https://github.com/efcore-encryption/EntityFrameworkCore.Crypto.DataEncryption/blob/main/ROADMAP.md) for details.

| Version | Target & Tier | Feature Area | Description |
|---|---|---|---|
| **v11.1** | Q3 2027 • Enterprise | 🏢 **Multi-Tenant Key Isolation** | Automatic per-tenant key derivation (`ITenantKeyProvider`) for zero-cross-tenant-data risk in SaaS. |
| **v11.2** | Q4 2027 • Enterprise | 🎭 **Role-Based Dynamic Data Masking** | Mask sensitive fields (`****-4321`, `a***@corp`) based on active user context and authorization roles. |
| **v11.3** | Q1 2028 • Enterprise | 🔍 **Fuzzy & Prefix Searchable Encryption** | N-gram / Trigram and `StartsWith` encrypted search without decrypting data server-side. |
| **v11.6** | Q4 2028 • Community & Enterprise | 🚀 **Zero-Downtime CLI Migration Tool** | Standalone global CLI tool (`dotnet ef-crypto migrate`) for background bulk batch encryption. |
| **v12.1** | Q1 2029 • Enterprise | 🛡️ **Hardware Security Module (HSM)** | Native PKCS#11 / YubiHSM / AWS CloudHSM support (FIPS 140-2 Level 3). |

👉 **For comprehensive technical specifications and API previews, see [ROADMAP.md](https://github.com/efcore-encryption/EntityFrameworkCore.Crypto.DataEncryption/blob/main/ROADMAP.md).**

---

## Plan Tiers & Licensing

The core field encryption capabilities, blind indexing, cloud KMS caching, deterministic detectors, and convention auto-encryption are available under the **Community** plan (free for evaluation, OSS, and projects under $2,000/yr revenue). Advanced ML classification, Crypto Sentinel anomaly detection, automated email/webhook alerts, audit trail, and compliance evidence packs require an **Enterprise** commercial license key.

| Capability | Community (Free / Evaluation) | Enterprise ($2,999/yr or $5,999/5-yr) |
|---|:---:|:---:|
| Field Encryption (AES-GCM / AES-CBC) | :white_check_mark: | :white_check_mark: |
| Rich Types (`long`, `decimal`, `double`, `Dictionary`, JSON, Owned) | :white_check_mark: | :white_check_mark: |
| Cloud KMS (Azure Key Vault / AWS KMS / HashiCorp Vault) | :white_check_mark: | :white_check_mark: |
| Key Rotation & Migration Bridge | :white_check_mark: | :white_check_mark: |
| Convention Auto-Encryption (`UseAutoEncryption`) | :white_check_mark: | :white_check_mark: |
| Searchable Blind Indexing (`HasBlindIndex`) | :white_check_mark: | :white_check_mark: |
| Deterministic PII Detectors (Aadhaar, CC, IBAN, PAN, SSN) | :white_check_mark: | :white_check_mark: |
| ML-Powered Text Classifier | :x: | :white_check_mark: |
| Crypto Sentinel Anomaly Detection | :x: | :white_check_mark: |
| Multi-Channel Alerts (SMTP / Webhook / Custom) | :x: | :white_check_mark: |
| Compliance Evidence Pack (DPDP / GDPR Export) | :x: | :white_check_mark: |
| Decryption Audit Trail Interceptor | :x: | :white_check_mark: |
| Developers & Applications | Up to 2 Devs / 1 Project | **Unlimited Developers & Projects** |
| Dedicated Support & SLA | Community | **Priority Support (< 1 Business Day / 1 Hour)** |

For commercial pricing, licenses, and enterprise support:
👉 **[https://efcore-encryption.com/#plans](https://efcore-encryption.com/#plans)**

---

## Security & Cryptographic Architecture

For detailed threat models, cryptographic design rationale (AES-256-GCM AEAD, envelope key caching, nonce generation), and vulnerability tracking, see **[SECURITY.md](SECURITY.md)**.

- **In-Process Cryptography**: All cryptographic operations run 100% in-process. Private keys are never generated, stored, or transmitted externally.
- **Tamper Resistance**: AES-256-GCM AEAD with 128-bit authentication tags ensures tampered, truncated, or forged ciphertext fails to decrypt rather than silently returning corrupted data.
- **Security Disclosures & Audits**: For vulnerability reporting policies and audit records, see [SECURITY.md](SECURITY.md).

---

## Enterprise & Commercial Support

- **Website**: [https://efcore-encryption.com/](https://efcore-encryption.com/)
- **Documentation**: [https://efcore-encryption.com/docs](https://efcore-encryption.com/docs)
- **The Complete Guide**: [docs/COMPLETE_GUIDE.md](docs/COMPLETE_GUIDE.md)
- **Product Roadmap**: [ROADMAP.md](ROADMAP.md)
- **Security Policy & Threat Model**: [SECURITY.md](SECURITY.md)
- **Issues & Inquiries**: [GitHub Issues](https://github.com/efcore-encryption/EntityFrameworkCore.Crypto.DataEncryption/issues)

---

## Thanks

efcore-encryption.com would like to thank all the contributors and community members who support and improve this project.
