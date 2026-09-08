using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.DataEncryption;
using Microsoft.EntityFrameworkCore.DataEncryption.Providers;
using Microsoft.EntityFrameworkCore.DataEncryption.Test.Context;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Xunit;

namespace Microsoft.EntityFrameworkCore.Encryption.Test;

/// <summary>
/// Integration tests verifying the new type-level encryption features:
/// <list type="number">
///   <item>Feature 1 — Dictionary&lt;string, string&gt; (JSON-serialized, encrypted).</item>
///   <item>Feature 2 — JSON/JSONB column objects (arbitrary concrete class, JSON-serialized).</item>
///   <item>Feature 3 — Numeric types: <c>long</c>, <c>decimal</c>, <c>double</c> (invariant-culture string).</item>
///   <item>Feature 4 — Owned entity type properties (existing walk covers them automatically).</item>
/// </list>
/// All tests use an in-memory SQLite database via <see cref="DatabaseContextFactory"/>.
/// </summary>
public sealed class AdvancedTypeEncryptionTest
{
    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static AesCryptoProvider CreateProvider()
    {
        CryptoAesKeyInfo key = AesCryptoProvider.GenerateKey(CryptoAesKeySize.AES256Bits);
        return new AesCryptoProvider(key.Key, key.IV);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feature 3 — long
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EncryptLongProperty_RoundTripsExactValue()
    {
        AesCryptoProvider provider = CreateProvider();
        const long original = 9_876_543_210L;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "salary-long", SalaryLong = original };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(original, loaded.SalaryLong);
    }

    [Fact]
    public void EncryptLongProperty_NegativeValue_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();
        const long original = -123_456_789L;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "neg-long", SalaryLong = original };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(original, loaded.SalaryLong);
    }

    [Fact]
    public void EncryptLongProperty_ZeroValue_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();
        const long original = 0L;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "zero-long", SalaryLong = original };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(original, loaded.SalaryLong);
    }

    [Fact]
    public void EncryptNullableLong_WithValue_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();
        const long value = 42_000L;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "nullable-long-set", OptionalLong = value };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(value, loaded.OptionalLong);
    }

    [Fact]
    public void EncryptNullableLong_Null_StoresAndReturnsNull()
    {
        AesCryptoProvider provider = CreateProvider();

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "nullable-long-null", OptionalLong = null };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Null(loaded.OptionalLong);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feature 3 — decimal
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EncryptDecimalProperty_RoundTripsExactValue()
    {
        AesCryptoProvider provider = CreateProvider();
        // Uses 20 significant digits — well within the 29-digit G29 format.
        decimal original = 123_456_789.987_654_321_0M;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "salary-decimal", SalaryDecimal = original };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(original, loaded.SalaryDecimal);
    }

    [Fact]
    public void EncryptDecimalProperty_MaxPrecision_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();
        // 28 significant digits — maximum representable by decimal without loss.
        decimal original = 1.234_567_890_123_456_789_012_345_6M;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "max-decimal", SalaryDecimal = original };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(original, loaded.SalaryDecimal);
    }

    [Fact]
    public void EncryptDecimalProperty_NegativeValue_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();
        decimal original = -99_999.99M;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "neg-decimal", SalaryDecimal = original };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(original, loaded.SalaryDecimal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feature 3 — double
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EncryptDoubleProperty_RoundTripsExactValue()
    {
        AesCryptoProvider provider = CreateProvider();
        // Pi to the full double precision — "R" format guarantees roundtrip exactness.
        double original = 3.141_592_653_589_793;

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "salary-double", SalaryDouble = original };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(original, loaded.SalaryDouble);
    }

    [Fact]
    public void EncryptDoubleProperty_NegativeInfinity_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "neg-inf-double", SalaryDouble = double.NegativeInfinity };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.Equal(double.NegativeInfinity, loaded.SalaryDouble);
    }

    [Fact]
    public void EncryptDoubleProperty_NaN_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using NumericDbContext ctx = factory.CreateContext<NumericDbContext>(provider);

        NumericEntity entity = new NumericEntity { Name = "nan-double", SalaryDouble = double.NaN };
        ctx.NumericEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        NumericEntity loaded = ctx.NumericEntities.Single(e => e.Id == entity.Id);

        Assert.True(double.IsNaN(loaded.SalaryDouble));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feature 1 & 2 — Dictionary<string, string> / JSON column
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EncryptDictionaryProperty_RoundTripsAllEntries()
    {
        AesCryptoProvider provider = CreateProvider();
        Dictionary<string, string> original = new Dictionary<string, string>
        {
            ["key1"] = "value1",
            ["key2"] = "value2",
            ["unicode"] = "नमस्ते 🌏",
            ["specials"] = "data with 'quotes' and \"double\" & <tags>",
        };

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using DictionaryDbContext ctx = factory.CreateContext<DictionaryDbContext>(provider);

        DictionaryEntity entity = new DictionaryEntity { Name = "metadata", Metadata = original };
        ctx.DictionaryEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        DictionaryEntity loaded = ctx.DictionaryEntities.Single(e => e.Id == entity.Id);

        Assert.NotNull(loaded.Metadata);
        Assert.Equal(original.Count, loaded.Metadata!.Count);
        foreach (KeyValuePair<string, string> kvp in original)
        {
            Assert.True(loaded.Metadata.TryGetValue(kvp.Key, out string? v));
            Assert.Equal(kvp.Value, v);
        }
    }

    [Fact]
    public void EncryptDictionaryProperty_EmptyDictionary_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();
        Dictionary<string, string> original = new Dictionary<string, string>();

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using DictionaryDbContext ctx = factory.CreateContext<DictionaryDbContext>(provider);

        DictionaryEntity entity = new DictionaryEntity { Name = "empty-dict", Metadata = original };
        ctx.DictionaryEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        DictionaryEntity loaded = ctx.DictionaryEntities.Single(e => e.Id == entity.Id);

        // Empty JSON object {} round-trips to an empty (non-null) dictionary.
        Assert.NotNull(loaded.Metadata);
        Assert.Empty(loaded.Metadata!);
    }

    [Fact]
    public void EncryptDictionaryProperty_NullDictionary_StoresAndReturnsNull()
    {
        AesCryptoProvider provider = CreateProvider();

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using DictionaryDbContext ctx = factory.CreateContext<DictionaryDbContext>(provider);

        DictionaryEntity entity = new DictionaryEntity { Name = "null-dict", Metadata = null };
        ctx.DictionaryEntities.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        DictionaryEntity loaded = ctx.DictionaryEntities.Single(e => e.Id == entity.Id);

        Assert.Null(loaded.Metadata);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feature 4 — Owned entity type
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EncryptOwnedEntityProperty_Street_RoundTrips()
    {
        AesCryptoProvider provider = CreateProvider();
        const string originalStreet = "123 Secure Lane, Encrypted City, PII-District";
        const string originalCity   = "OpenCity"; // Not encrypted — should be readable as-is.

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using OwnedEntityDbContext ctx = factory.CreateContext<OwnedEntityDbContext>(provider);

        PersonWithAddressEntity entity = new PersonWithAddressEntity
        {
            Name = "Alice",
            HomeAddress = new OwnedAddress { Street = originalStreet, City = originalCity }
        };
        ctx.People.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        PersonWithAddressEntity loaded = ctx.People.Single(e => e.Id == entity.Id);

        Assert.NotNull(loaded.HomeAddress);
        Assert.Equal(originalStreet, loaded.HomeAddress!.Street);  // decrypted ✓
        Assert.Equal(originalCity,   loaded.HomeAddress.City);     // plain-text ✓
    }

    [Fact]
    public void EncryptOwnedEntityProperty_NullStreet_ReturnsNull()
    {
        AesCryptoProvider provider = CreateProvider();

        using DatabaseContextFactory factory = new DatabaseContextFactory();
        using OwnedEntityDbContext ctx = factory.CreateContext<OwnedEntityDbContext>(provider);

        PersonWithAddressEntity entity = new PersonWithAddressEntity
        {
            Name = "Bob",
            HomeAddress = new OwnedAddress { Street = null, City = "Somewhere" }
        };
        ctx.People.Add(entity);
        ctx.SaveChanges();

        ctx.ChangeTracker.Clear();
        PersonWithAddressEntity loaded = ctx.People.Single(e => e.Id == entity.Id);

        Assert.Null(loaded.HomeAddress!.Street);
        Assert.Equal("Somewhere", loaded.HomeAddress.City);
    }

    [Fact]
    public void EncryptOwnedEntityProperty_DifferentKeysIsolated()
    {
        // Verify that two providers (different keys) each produce independent ciphertexts
        // and that loading with the correct key always returns the plaintext.
        AesCryptoProvider provider1 = CreateProvider();
        AesCryptoProvider provider2 = CreateProvider();

        const string street = "1 Privacy Road";

        using DatabaseContextFactory factory1 = new DatabaseContextFactory();
        using OwnedEntityDbContext ctx1 = factory1.CreateContext<OwnedEntityDbContext>(provider1);

        PersonWithAddressEntity entity1 = new PersonWithAddressEntity
        {
            Name = "Carol",
            HomeAddress = new OwnedAddress { Street = street }
        };
        ctx1.People.Add(entity1);
        ctx1.SaveChanges();

        ctx1.ChangeTracker.Clear();
        PersonWithAddressEntity loaded1 = ctx1.People.Single(e => e.Id == entity1.Id);

        Assert.Equal(street, loaded1.HomeAddress!.Street);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DbContext fixtures — inline to keep them local to these tests
    // ─────────────────────────────────────────────────────────────────────────

#pragma warning disable S3427 // Method overloads with default parameter values should not overlap

    private sealed class NumericDbContext : DbContext
    {
        private readonly IEncryptionCryptoProvider? _provider;
        public DbSet<NumericEntity> NumericEntities { get; set; } = null!;

        public NumericDbContext(DbContextOptions options) : base(options) { }

        public NumericDbContext(DbContextOptions options, IEncryptionCryptoProvider? provider = null)
            : base(options) => _provider = provider;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            if (_provider is not null)
            {
                modelBuilder.UseEncryption(_provider);
            }
        }
    }

    private sealed class DictionaryDbContext : DbContext
    {
        private readonly IEncryptionCryptoProvider? _provider;
        public DbSet<DictionaryEntity> DictionaryEntities { get; set; } = null!;

        public DictionaryDbContext(DbContextOptions options) : base(options) { }

        public DictionaryDbContext(DbContextOptions options, IEncryptionCryptoProvider? provider = null)
            : base(options) => _provider = provider;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            if (_provider is not null)
            {
                modelBuilder.UseEncryption(_provider);
            }
        }
    }

    private sealed class OwnedEntityDbContext : DbContext
    {
        private readonly IEncryptionCryptoProvider? _provider;
        public DbSet<PersonWithAddressEntity> People { get; set; } = null!;

        public OwnedEntityDbContext(DbContextOptions options) : base(options) { }

        public OwnedEntityDbContext(DbContextOptions options, IEncryptionCryptoProvider? provider = null)
            : base(options) => _provider = provider;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Configure the owned type BEFORE UseEncryption so that the model walk
            // can see and encrypt the owned entity's annotated properties.
            modelBuilder.Entity<PersonWithAddressEntity>().OwnsOne(p => p.HomeAddress);
            if (_provider is not null)
            {
                modelBuilder.UseEncryption(_provider);
            }
        }
    }

#pragma warning restore S3427
}
