# EntityFrameworkCore.Crypto.DataEncryption — The Complete Guide

**Core package v10.1.0 · ML companion v1.0.0 · net9.0 / net10.0 · EF Core 9/10**

Field-level encryption for EF Core, plus an ML-powered companion that finds the PII you missed, watches decryption for breach patterns, and produces audit-ready compliance evidence.

---

## Contents

1. [What this is](#1-what-this-is)
2. [Architecture at a glance](#2-architecture-at-a-glance)
3. [Installation](#3-installation)
4. [Five-minute quick start](#4-five-minute-quick-start)
5. [Encrypting fields — manual mode](#5-encrypting-fields--manual-mode)
6. [Auto-encryption by convention](#6-auto-encryption-by-convention)
7. [Searchable encrypted columns — blind indexes](#7-searchable-encrypted-columns--blind-indexes)
8. [PII detection](#8-pii-detection)
9. [Scanning](#9-scanning)
10. [Crypto Sentinel — anomaly detection](#10-crypto-sentinel--anomaly-detection)
11. [Alerting](#11-alerting)
12. [Compliance reports](#12-compliance-reports)
13. [Licensing and tiers](#13-licensing-and-tiers)
14. [Performance guide](#14-performance-guide)
15. [Upgrading from v10.0.x](#15-upgrading-from-v100x)
16. [Security architecture and threat model](#16-security-architecture-and-threat-model)
17. [Configuration reference](#17-configuration-reference)
18. [Troubleshooting and FAQ](#18-troubleshooting-and-faq)

---

## 1. What this is

**`EntityFrameworkCore.Crypto.DataEncryption`** (core, MIT) encrypts individual entity properties transparently through EF Core value converters. Data is encrypted before it leaves your process and decrypted after it returns — the database, its backups, and anyone reading them see only ciphertext. You bring the keys; the library never generates, stores, or transmits key material.

**`EntityFrameworkCore.Crypto.DataEncryption.ML`** (companion, freemium) adds the operational layer enterprises actually get audited on:

| Pillar | What it does |
|---|---|
| **Find** | Scans your model and live data for unencrypted PII — checksum-verified detectors plus an ML classifier |
| **Encrypt** | Optional secure-by-default mode: PII columns encrypt by convention, opting out is the explicit act |
| **Search** | Blind indexes restore fast equality lookups on encrypted columns |
| **Watch** | Sentinel learns your decryption baseline and alerts on exfiltration-shaped spikes in seconds |
| **Prove** | One call produces a DPDP / GDPR Art. 32 evidence pack: inventory, coverage, findings, accepted risks, alert history |

Everything runs inside your process. No telemetry, no phone-home, no vendor cloud.

## 2. Architecture at a glance

```
┌──────────────────────────── Your application process ────────────────────────────┐
│                                                                                  │
│  EF Core query/save                                                              │
│      │                                                                           │
│      ▼                                                                           │
│  Value converters ──── IEncryptionCryptoProvider (YOUR key)                      │
│      │                    ├─ AesCryptoProvider        (CBC — classic)            │
│      │                    ├─ AesGcmCryptoProvider     (AEAD + key rotation)      │
│      │                    └─ MigrationCryptoProvider  (optional CBC→GCM bridge)  │
│      │                                                                           │
│      ├──────────────► BlindIndexInterceptor ── HMAC shadow columns (searchable)  │
│      │                                                                           │
│      └── telemetry ─► CryptoOperationMonitor ─► AnomalyDetectionService (SSA)    │
│                                                        │                         │
│  SensitiveDataScanner ◄── model + sampled data         ▼                         │
│         │                                        AlertDispatcher                 │
│         ▼                                        (digest·retry·dead-letter)      │
│  ComplianceReportGenerator                              │                        │
│         │                                    ┌──────────┼──────────┐             │
│         ▼                                    ▼          ▼          ▼             │
│  JSON + print-ready HTML                  ILogger    SMTP     Signed webhook     │
└──────────────────────────────────────────────────────────────────────────────────┘
                    Database sees ciphertext + keyed hashes only
```

## 3. Installation

```bash
dotnet add package EntityFrameworkCore.Crypto.DataEncryption        # core (MIT, free)
dotnet add package EntityFrameworkCore.Crypto.DataEncryption.ML     # companion (freemium)
```

Requirements: .NET 9 or 10, EF Core 9/10, any relational provider (SQL Server, PostgreSQL, MySQL, SQLite, Oracle…). The ML package pulls Microsoft.ML 4.x and MailKit.

## 4. Five-minute quick start

```csharp
// Program.cs
builder.Services.AddDataEncryptionML(options =>
{
    options.LicenseKey = builder.Configuration["EfCryptoML:LicenseKey"];   // omit → Community tier

    options.Email = new SmtpEmailOptions        // your SMTP, your credentials
    {
        Host = builder.Configuration["Smtp:Host"]!,
        Username = builder.Configuration["Smtp:User"],
        Password = builder.Configuration["Smtp:Pass"],
        From = "security@yourapp.example",
        To = { "dpo@yourapp.example" },
    };
});

builder.Services.AddStartupSensitiveDataScan<AppDbContext>();   // scan once after boot

builder.Services.AddDbContext<AppDbContext>((sp, o) => o
    .UseSqlServer(connectionString)
    .UseCryptoSentinel(sp));                                    // per-entity decrypt telemetry
```

```csharp
// AppDbContext.cs
public class AppDbContext(DbContextOptions<AppDbContext> options, ICryptoOperationMonitor monitor)
    : DbContext(options)
{
    private static readonly AesGcmCryptoProvider Provider = new(LoadKeyFromVault());

    protected override void OnModelCreating(ModelBuilder modelBuilder)
        => modelBuilder.UseEncryption(monitor.Instrument(Provider));   // or UseAutoEncryption — §6
}
```

Mark a field, done:

```csharp
public class Customer
{
    [CryptoEncrypted]
    public string AadhaarNumber { get; set; }
}
```

## 5. Encrypting fields — manual mode

Manual mode is the default philosophy: **nothing encrypts unless you mark it.**

### Marking

```csharp
// Attribute — with optional storage format:
[CryptoEncrypted]                              public string Aadhaar { get; set; }
[CryptoEncrypted(CryptoStorageFormat.Binary)]  public string Pan { get; set; }

// Fluent — inside OnModelCreating:
modelBuilder.Entity<Customer>().Property(c => c.Mobile).IsEncrypted();
```

### Activation

The **last line** of `OnModelCreating`, after all entity configuration:

```csharp
modelBuilder.UseEncryption(provider);
```

Without activation, attributes do nothing — this is deliberate: encryption is always an explicit, visible decision.

### Providers

| Provider | Use when | Properties |
|---|---|---|
| `AesCryptoProvider(key, iv)` | Existing v10.0.x apps; deterministic ciphertext acceptable | AES-CBC, your static IV; identical plaintexts → identical ciphertexts |
| `AesGcmCryptoProvider(key)` | New deployments (recommended) | AEAD: random 96-bit nonce per value, 128-bit tamper-detection tag, optional associated data, key-ring rotation via key-id byte |
| `MigrationCryptoProvider(gcm, legacy)` | Optionally moving CBC data to GCM — see §15 | Writes GCM, reads both, counters signal completion |

GCM envelope wire format: `[version:1][keyId:1][nonce:12][tag:16][ciphertext:n]`.

### Key rotation (GCM)

```csharp
var provider = new AesGcmCryptoProvider(
    primaryKey: new AesGcmKey(1, newKey),                    // all new writes
    decryptionKeys: new[] { new AesGcmKey(0, oldKey) });     // old rows keep reading
```

Re-encrypt at your leisure; the key-id byte in each value routes decryption automatically.

### Key management rules

- **You own the keys.** The library has no code path that generates, selects, or persists a key on its own. `GenerateKey()` is a utility you may call — the library never does.
- Load keys from Azure Key Vault / AWS KMS / environment at startup; never hardcode, never commit.
- Use a **separate** key for blind indexes (§7) — different attack surface, independent rotation.
- Losing the key means losing the data. Escrow accordingly.

## 6. Auto-encryption by convention

Secure-by-default mode: PII columns encrypt automatically; staying plaintext becomes the explicit act.

```csharp
modelBuilder.UseAutoEncryption(monitor.Instrument(Provider));   // replaces UseEncryption
```

**What encrypts automatically:**

1. Every `[SensitiveData(PiiKind.X)]`-declared property — always.
2. Any string/byte[] property whose name scores ≥ `MinNameConfidence` (default **0.8**) for an **identifier-like kind**: Aadhaar, PAN, payment card, bank account, national ID, wallet, email, phone. So `AadhaarNumber`, `BankAccountNumber`, `PassportNo`, `WalletAddress`, `EmailAddress` are protected with zero configuration.

**What deliberately does NOT auto-encrypt:** `PersonName`, `Address`, `MonetaryAmount` — the columns applications filter, `LIKE`-search, and sort on, which encryption breaks server-side. Opt in knowingly:

```csharp
options.AutoEncrypt.Kinds.Add(PiiKind.PersonName);
```

**Per-field opt-out:**

```csharp
[DoNotEncrypt(Reason = "search screen filters on this column")]
public string LastName { get; set; }        // plaintext; scanner still flags it (visible risk)

[DoNotEncrypt, ScanExempt("Search requirement; DLP monitored", ApprovedBy = "CISO, 2026-07-01")]
public string City { get; set; }            // plaintext + recorded as accepted risk
```

`[ScanExempt]` alone and `options.AutoEncrypt.ExcludedProperties` also opt out. Every decision is logged and returned in `AutoEncryptionResult` — nothing silent.

**Brownfield workflow:** `options.AutoEncrypt.DryRun = true` → review the log of what *would* change → backfill existing plaintext rows (§15 pattern) → flip DryRun off.

## 7. Searchable encrypted columns — blind indexes

Random nonces mean `WHERE Email = @x` can never match server-side. Blind indexes fix **equality** lookups: a keyed HMAC-SHA256 of the normalized plaintext lives in an auto-created, auto-indexed `varchar(32)` shadow column, synced on every save.

```csharp
var hasher = new BlindIndexHasher(blindIndexKey);            // DEDICATED key, not the encryption key

modelBuilder.Entity<User>().Property(u => u.Email)
    .IsEncrypted()
    .HasBlindIndex();                                        // creates EmailBlindIndex + DB index

optionsBuilder.AddInterceptors(new BlindIndexInterceptor(hasher));

var user = await ctx.Users
    .WhereBlindEquals(nameof(User.Email), email, hasher)     // index seek, not a scan
    .FirstOrDefaultAsync();
```

Facts: equality and joins only (no `LIKE`/ranges — inherent to hashing); case-insensitive normalization by default (`caseInsensitive: false` for tokens); the hash reveals nothing without the key; scanner and compliance ignore shadow columns; add an EF migration after configuring and backfill hashes once for existing rows.

## 8. PII detection

Three evidence layers, strongest first.

### Deterministic detectors (all tiers)

| Detector | Verification | Confidence |
|---|---|---|
| Aadhaar | 12 digits, Verhoeff checksum, UIDAI first-digit rule | 1.0 |
| Payment card | 13–19 digits, Luhn, issuer plausibility | 0.97 |
| IBAN | ISO 13616: 70+ country registry, length, **mod-97** | 1.0 |
| PAN | Structure + holder-type character | 0.95 |
| US SSN | Hyphenated or SSN-context, SSA validity rules | 0.90–0.95 |
| Bank account | IFSC (structural) or 9–18 digits in banking context, with Aadhaar/card/mobile disambiguation | 0.90–1.0 |
| Crypto wallet | Bitcoin-family **Base58Check double-SHA256**, Bech32 **BIP-173 polymod**, Ethereum structural, UPI VPA | 0.80–1.0 |
| Email / Phone | RFC-lite / Indian mobile + E.164 | 0.90–1.0 |

Checksum verification is the point: a Luhn-valid card or mod-97-valid IBAN in an unencrypted column is a fact, not a guess — false-positive rates are cryptographically or mathematically bounded.

### Name heuristics (all tiers)

~140-token weighted vocabulary across banking (routing, sort code, BSB, SWIFT, IFSC), amounts (salary, balance, income, CTC), names (first/middle/last/given/family/maiden), national IDs (SSN, NINO, SIN, TFN, NRIC, CPF, CURP, DNI, PESEL, passport), wallets (BTC, ETH, PayPal, Venmo, Paytm, PhonePe), credentials and health terms. CamelCase/snake_case/acronym-aware tokenizer (`PANNumber` → `pan` + `number`).

### ML classifier (Pro/Enterprise)

ML.NET multiclass text model for `PersonName` / `Address` / `FreeTextPii`. Trains deterministically on first use from an embedded corpus (<1 s), caches to disk, extensible with your domain examples via `AdditionalCorpusPath` (TSV `Label<TAB>Text`).

### Control attributes

| Attribute | Meaning | Scanner | Auto-encrypt |
|---|---|---|---|
| `[CryptoEncrypted]` | Encrypt this | Counts as protected | Left as-is |
| `[SensitiveData(kind)]` | This is PII | Unencrypted ⇒ **Critical** finding | Encrypts it |
| `[DoNotEncrypt]` | Keep plaintext | Still flags (visible risk) | Skips it |
| `[ScanExempt("why")]` | Accepted risk | Suppresses, **records** in report | Skips it |

Precedence: `ScanExempt` > `DoNotEncrypt` > `SensitiveData` > heuristics.

### Custom rules (all tiers)

```csharp
options.Detection.NameTokens["employeecode"] = new(PiiKind.FreeTextPii, 0.9);
options.Detection.ValueRules.Add(new CustomValueRule
{
    Name = "EmployeeId", Kind = PiiKind.FreeTextPii,
    Pattern = @"^EMP-\d{6}$", Confidence = 0.95, Deterministic = true,
});
```

Patterns validate at startup; each runs with a 250 ms timeout at scan time.

## 9. Scanning

```csharp
// On demand:
ScanReport report = await scanner.ScanAsync(dbContext);

// Once at startup (findings → alert pipeline):
builder.Services.AddStartupSensitiveDataScan<AppDbContext>();
```

The scanner walks the model, applies name heuristics, samples the first `SampleSize` (100) non-empty values per unencrypted string column with `AsNoTracking()` (query filters respected, encrypted columns never sampled), runs detectors → ML → name-guided shape corroboration, and maps severity: deterministic data evidence ⇒ **Critical**, ML evidence or strong name ⇒ **Warning**, moderate name ⇒ **Info**. Per-entity fault isolation; O(1) cost w.r.t. table size.

`ScanReport` carries findings, counts, coverage, duration, tier, and `Exemptions` (the accepted-risk ledger).

## 10. Crypto Sentinel — anomaly detection

The breach pattern that matters: an attacker with app-level access bulk-reads encrypted rows, and *your own application* dutifully decrypts them. Sentinel catches the shape of that.

- The instrumented provider and a materialization interceptor stream events (`crypto.decrypt`, `entity:Customer`, …) into a bounded, drop-on-full channel — **one lock-free write, ~tens of ns, never blocks a query**.
- Per series, ML.NET SSA spike detection (`DetectSpikeBySsa`) learns a baseline over `TrainingWindow` intervals (default 120 × 1 s), then scores every interval.
- A positive spike with ≥ `MinEventsForAlert` (50) events raises a Warning; ≥ `CriticalEventsThreshold` (500) raises Critical immediately. Per-series cooldown (5 min) stops storms. `HardRateLimitPerInterval` gives an absolute guard that works from second one.

Tuning: raise `MinEventsForAlert` to your P99 legitimate burst; set the hard limit to "no human workflow ever does this" (e.g., 5,000 decrypts/second).

## 11. Alerting

**Channels:** `ILogger` (always on — an alert is never invisible), SMTP email via MailKit (Pro+; *your* SMTP server and credentials — Microsoft 365, Gmail app passwords, SES, Zoho all documented), HMAC-signed webhooks (Pro+; `X-RLML-Signature: sha256=<hex>` over the raw body), and custom `IAlertChannel` implementations (Enterprise).

**Pipeline:** Critical alerts deliver on the next tick; everything else batches into per-(kind, source) digest windows (default 15 min) and ships as one email. Failures retry with backoff (1 s → 5 s → 30 s), then dead-letter into a bounded in-memory ledger surfaced in logs and the compliance report. Pending digests flush on shutdown. Producers never block: the intake is a bounded channel that counts drops rather than stalling your app.

## 12. Compliance reports

```csharp
ComplianceReport report = generator.Generate(dbContext,
    "AES-256-GCM, random 96-bit nonce per value, key-ring rotation",
    scanReport, recentAlerts);

File.WriteAllText("evidence.html", generator.ToHtml(report));   // print-ready A4
File.WriteAllText("evidence.json", generator.ToJson(report));   // machine-readable
```

Contents: encryption configuration statement · full encrypted-property inventory (entity, property, column, storage format) · coverage % · outstanding findings by severity · **accepted risks** (every `[ScanExempt]` with justification and sign-off) · recent alert history · dead-lettered deliveries. Enterprise tier; the API throws a clear `LicenseFeatureException` below it rather than emitting an incomplete document.

Maps to: India **DPDP Act 2023** §8 reasonable security safeguards · **GDPR Art. 32** pseudonymisation/encryption evidence · PCI-DSS Req. 3 support · SOC 2 / ISO 27001 control evidence.

## 13. Licensing and tiers
| Capability | Community (free) | Pro — $59/dev/yr (₹1,999 India) | Enterprise — $599/org/yr |
|---|---|---|---|
| Field encryption (core, MIT) | ✅ | ✅ | ✅ |
| Deterministic detectors + heuristics + custom rules | ✅ | ✅ | ✅ |
| Auto-encryption, blind indexes, all attributes | ✅ | ✅ | ✅ |
| ML classifier (names/addresses/free text) | — | ✅ | ✅ |
| Crypto Sentinel | — | ✅ | ✅ |
| Email + webhook alert channels | — | ✅ | ✅ |
| Compliance report export | — | — | ✅ |
| Custom alert channels | — | — | ✅ |

License keys (`RLML1.…`) are ECDSA P-256-signed and validated **fully offline** — no activation server, no telemetry, no machine binding, air-gap friendly. A missing/expired/invalid key **never breaks your application**: features degrade to Community with one clear warning each; explicit Enterprise APIs throw instead of silently truncating. Expiry warnings arrive through the same alert pipeline 14 days out.

### Enforcement: warn locally, fail in the cloud

By default the library distinguishes **where** it runs and reacts accordingly when paid features are configured without a valid license:

| Environment | Unlicensed behavior |
|---|---|
| Local development (laptop, `ASPNETCORE_ENVIRONMENT=Development`, debugger) | **Warns** and continues in Community tier — you're never blocked while building |
| Container, Kubernetes, or managed cloud (Azure/AWS/GCP/Heroku) | **Fails startup** with a `LicenseValidationException` — an unlicensed production deployment stops loudly instead of silently degrading |

Detection reads only environment variables and well-known container/orchestrator markers (`KUBERNETES_SERVICE_HOST`, the k8s service-account token, `DOTNET_RUNNING_IN_CONTAINER`, `/.dockerenv`, container cgroups, and cloud platform variables). **No network or metadata calls.** Kubernetes and managed-cloud signals are always treated as production (they can't occur on a laptop); a plain container is treated as production unless the hosting environment is explicitly `Development`.

Configure it via `options.Enforcement`:

```csharp
builder.Services.AddDataEncryptionML(o =>
{
    o.LicenseKey = cfg["EfCryptoML:LicenseKey"];

    o.Enforcement.Mode = LicenseEnforcementMode.Auto;   // default: warn local, fail cloud
    // o.Enforcement.Mode = LicenseEnforcementMode.Strict;   // fail everywhere, even local
    // o.Enforcement.Mode = LicenseEnforcementMode.WarnOnly; // never fail (not recommended)

    // o.Enforcement.TreatAsProduction = true;   // force-fail even in dev (e.g. CI gate)
    // o.Enforcement.TreatAsProduction = false;  // force-allow (e.g. an unlicensed CI job)
    // o.Enforcement.AllowEnvironmentOverride = false;  // forbid the runtime WarnOnly escape hatch
});
```

**Operational safety valve.** Unless you set `AllowEnvironmentOverride = false`, an operator can set the environment variable `EFCRYPTOML_LICENSE_ENFORCEMENT=WarnOnly` to start a service unlicensed in a genuine emergency (for example, a false-positive environment detection or a licensing incident). Every use is logged prominently and surfaced for audit — it exists so a licensing edge case can't take down a paying customer's service without a redeploy, not as a way to run unlicensed indefinitely.

**Honest scope.** This is startup enforcement with an audit trail, not DRM. Because the core is MIT and runs inside your own process, a determined party could bypass it — the goal is to make *accidental* unlicensed production deployment fail loudly (so honest teams know to buy) and to create a clear, logged record, exactly as commercial .NET components like Duende IdentityServer do. Note that Duende itself chooses to *warn rather than crash* in production to avoid taking down an auth server; this library defaults to failing because a data-protection dependency starting unlicensed is usually something you want caught before go-live. Switch to `WarnOnly` if you prefer Duende's warn-don't-crash posture.


## 14. Performance guide

| Path | Cost | At scale |
|---|---|---|
| Encrypt (push) | ~1–3 µs + 1 alloc per value (AES-NI) | 100k rows × 5 fields ≈ 0.5–1 s CPU — below DB commit time |
| Decrypt (pull) | ~1–2 µs per **materialized** value | 10k rows × 3 cols ≈ 30–90 ms; ~50–120k rows/s end-to-end |
| Projections skipping encrypted cols | **Zero** | `Select(new { o.Id, o.Status })` pays nothing |
| Blind-index HMAC | ~1 µs per indexed changed value | Negligible |
| Sentinel telemetry | ~tens of ns, lock-free, drop-on-full | Never blocks queries |
| Startup scan | `Take(100)` per column | Same cost at 1k or 500M rows |
| Storage | +30 B envelope; Base64 ×1.33 | Plan index/backup growth |

Disciplines: never filter/sort/`LIKE` directly on encrypted columns (blind indexes for equality; keep range-queried columns out of encryption); project only what you need; prefer `CryptoStorageFormat.Binary` for byte[] columns. Measure on your hardware: `dotnet run -c Release --project benchmarks/...` → `RowThroughputBenchmarks` reports µs/row for push, push+blind-index, and pull.

## 15. Upgrading from v10.0.x

**No migration is ever required.** Same APIs, same annotations, same `AesCryptoProvider(key, iv)` reading the same data. The ML package is a separate optional NuGet that recognizes your existing `[CryptoEncrypted]` model immediately. The library still never touches your keys.

*Optional*, if you ever choose GCM: deploy `MigrationCryptoProvider(gcm, legacy)` (reads both formats, writes GCM), run a one-time sweep (`entry.Property(x).IsModified = true; SaveChanges()` re-encrypts through the converter), watch `LegacyDecrypts` reach zero, swap in plain GCM. Staying on CBC forever is fully supported.

## 16. Security architecture and threat model

**Protects against:** database theft/leaked backups (ciphertext only) · DBA/insider reads of protected columns · tampering with GCM-protected values (auth tag) · bulk exfiltration through the app (Sentinel) · silent scope creep of unprotected PII (scanner) · undocumented risk acceptance (exemption ledger).

**Does not protect against (be honest with auditors):** a fully compromised app process holding the key · plaintext you log yourself · side channels in the database engine · quantum adversaries (AES-256 margin is the standard answer).

**Design guarantees:** keys are exclusively yours (no generation, storage, or transmission by the library) · zero network calls except the SMTP/webhooks *you* configure · offline license validation · bounded queues everywhere — under any load, the *detector* saturates before your application does · fail-safe defaults (invalid license → degrade and warn; scan error → skip entity and continue; channel down → retry, dead-letter, and log).

## 17. Configuration reference

```csharp
services.AddDataEncryptionML(o =>
{
    o.LicenseKey = "...";                                   // null → Community

    o.Detection.NameTokens["..."] = new(kind, weight);      // custom vocabulary
    o.Detection.ValueRules.Add(new CustomValueRule { ... });

    o.AutoEncrypt.MinNameConfidence = 0.8;                  // heuristic bar
    o.AutoEncrypt.Kinds.Add(PiiKind.PersonName);            // opt kinds in
    o.AutoEncrypt.DryRun = true;                            // evaluate first

    o.Scan.SampleSize = 100;                                // values per column
    o.Scan.IncludeDataSampling = true;
    o.Scan.MinNameConfidence = 0.5;  o.Scan.MinDataMatchRate = 0.1;
    o.Scan.ExcludedEntities.Add("AuditLog");
    o.Scan.StartupScanDelay = TimeSpan.FromSeconds(5);

    o.Sentinel.SamplingInterval = TimeSpan.FromSeconds(1);
    o.Sentinel.TrainingWindow = 120;                        // baseline intervals
    o.Sentinel.MinEventsForAlert = 50;
    o.Sentinel.CriticalEventsThreshold = 500;
    o.Sentinel.AlertCooldown = TimeSpan.FromMinutes(5);
    o.Sentinel.HardRateLimitPerInterval = 0;                // 0 = off

    o.Alerts.DigestWindow = TimeSpan.FromMinutes(15);
    o.Alerts.MaxRetryAttempts = 3;                          // delays 1s/5s/30s

    o.Email = new SmtpEmailOptions { Host, Port = 587, Username, Password, From, To, SubjectPrefix };
    o.Webhook = new WebhookOptions { Url, Secret, TimeoutSeconds = 15 };

    o.Classifier.ConfidenceThreshold = 0.7;
    o.Classifier.AdditionalCorpusPath = "domain-pii.tsv";
});
```

All configuration is validated eagerly at startup with actionable error messages — a typo fails the deploy, not the 3 a.m. alert.

## 18. Troubleshooting and FAQ

**Existing rows fail to decrypt after enabling encryption on a column.** Expected: pre-encryption values are plaintext. Backfill via the §15 sweep pattern before deploying.

**`WHERE` on an encrypted column returns nothing.** By design — see §7 for blind indexes, or keep that column unencrypted with `[ScanExempt]` documenting why.

**SMTP alerts aren't arriving.** Check logs — every failure is logged and dead-lettered; the logger channel always carries the alert regardless. Microsoft 365 needs SMTP AUTH enabled; Gmail needs an app password.

**Sentinel never fires.** It needs the training window (~2 min at defaults) and `MinEventsForAlert` events in one interval. For instant absolute protection set `HardRateLimitPerInterval`.

**Scanner flags a column I know is safe.** `[ScanExempt("reason")]` for an audited acceptance, or `ExcludedProperties` for a silent skip.

**Does anything leave my network?** Only the SMTP/webhook traffic you configure. License validation is offline. No telemetry exists.

**Can I run air-gapped?** Yes — keys, license, model training, and all detection are fully local.

**What happens when my license expires?** Warning alerts at ≤14 days; on expiry, Pro/Enterprise features stop with clear log messages and the application keeps running on Community behavior.

---

*Support: <https://github.com/RoyceLark/EntityFrameworkCore.Crypto.DataEncryption/issues> · Licensing: see README purchase links.*
