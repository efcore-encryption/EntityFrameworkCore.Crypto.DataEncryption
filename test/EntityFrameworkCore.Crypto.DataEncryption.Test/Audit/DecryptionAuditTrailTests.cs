using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.DataEncryption;
using Microsoft.EntityFrameworkCore.DataEncryption.ML.Audit;
using Microsoft.EntityFrameworkCore.DataEncryption.ML.Licensing;
using Microsoft.EntityFrameworkCore.DataEncryption.Providers;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Microsoft.EntityFrameworkCore.DataEncryption.ML.Test.Audit;

public class DecryptionAuditTrailTests
{
    private sealed class RecordingSink : IDecryptionAuditSink
    {
        public List<DecryptionAuditEvent> Events { get; } = new();
        public string Name => "recording";

        public Task PublishAsync(DecryptionAuditEvent auditEvent, CancellationToken cancellationToken)
        {
            lock (Events)
            {
                Events.Add(auditEvent);
            }

            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingSink : IDecryptionAuditSink
    {
        public string Name => "throwing";

        public Task PublishAsync(DecryptionAuditEvent auditEvent, CancellationToken cancellationToken)
            => throw new InvalidOperationException("simulated sink failure");
    }

    private static LicenseGate EnterpriseGate() => new(
        new LicenseValidationResult { Tier = LicenseTier.Enterprise, IsLicensed = true, Status = "test gate" },
        NullLogger<LicenseGate>.Instance);

    private static LicenseGate CommunityGate() => new(
        new LicenseValidationResult { Tier = LicenseTier.Community, IsLicensed = false, Status = "unlicensed" },
        NullLogger<LicenseGate>.Instance);

    private static DecryptionAuditEvent MakeEvent(string entityType = "Customer") => new()
    {
        EntityType = entityType,
        PropertyNames = new[] { "Ssn" },
    };

    [Fact]
    public void TryPublish_ReturnsFalse_WhenDisabled()
    {
        var options = new DecryptionAuditTrailOptions { Enabled = false };
        var trail = new DecryptionAuditTrail(Array.Empty<IDecryptionAuditSink>(), options, EnterpriseGate(), NullLogger<DecryptionAuditTrail>.Instance);

        bool result = trail.TryPublish(MakeEvent());

        Assert.False(result);
        Assert.Equal(0, trail.PublishedEvents);
    }

    [Fact]
    public void TryPublish_ReturnsFalse_WhenNotEnterpriseLicensed()
    {
        var options = new DecryptionAuditTrailOptions();
        var trail = new DecryptionAuditTrail(Array.Empty<IDecryptionAuditSink>(), options, CommunityGate(), NullLogger<DecryptionAuditTrail>.Instance);

        bool result = trail.TryPublish(MakeEvent());

        Assert.False(result);
    }

    [Fact]
    public async Task TryPublish_DeliversToAllSinks_WhenEnabledAndLicensed()
    {
        var sinkA = new RecordingSink();
        var sinkB = new RecordingSink();
        var options = new DecryptionAuditTrailOptions();
        var trail = new DecryptionAuditTrail(new IDecryptionAuditSink[] { sinkA, sinkB }, options, EnterpriseGate(), NullLogger<DecryptionAuditTrail>.Instance);

        bool result = trail.TryPublish(MakeEvent("Customer"));
        Assert.True(result);

        await trail.DrainOnceAsync(TestContext.Current.CancellationToken);

        Assert.Single(sinkA.Events);
        Assert.Single(sinkB.Events);
        Assert.Equal("Customer", sinkA.Events[0].EntityType);
        Assert.Equal(1, trail.PublishedEvents);
    }

    [Fact]
    public async Task TryPublish_CountsDrop_WhenIntakeBufferIsFull()
    {
        var options = new DecryptionAuditTrailOptions { ChannelCapacity = 16 };
        var trail = new DecryptionAuditTrail(Array.Empty<IDecryptionAuditSink>(), options, EnterpriseGate(), NullLogger<DecryptionAuditTrail>.Instance);

        var results = new List<bool>();
        for (int i = 0; i < 40; i++)
        {
            results.Add(trail.TryPublish(MakeEvent($"Entity{i}")));
        }

        Assert.Contains(false, results);
        Assert.True(trail.DroppedEvents > 0);

        // Drain what fit so the test doesn't leak an unread channel (not load-bearing for the assertions above).
        await trail.DrainOnceAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task DeliverAsync_LogsAndContinues_WhenOneSinkThrows()
    {
        var goodSink = new RecordingSink();
        var badSink = new ThrowingSink();
        var options = new DecryptionAuditTrailOptions();
        var trail = new DecryptionAuditTrail(new IDecryptionAuditSink[] { badSink, goodSink }, options, EnterpriseGate(), NullLogger<DecryptionAuditTrail>.Instance);

        trail.TryPublish(MakeEvent());

        // Must not throw even though badSink always throws.
        await trail.DrainOnceAsync(TestContext.Current.CancellationToken);

        Assert.Single(goodSink.Events);
    }

    // ---- Materialization interceptor ----

    public class AuditedCustomer
    {
        public int Id { get; set; }

        [CryptoEncrypted]
        public string? Ssn { get; set; }

        public string Name { get; set; } = string.Empty;
    }

    /// <summary>
    /// Every test in this class builds its own <see cref="AesGcmCryptoProvider"/> and expects
    /// <c>OnModelCreating</c> to bind the converter to THAT instance. EF Core's default model
    /// caching keys the compiled model on the DbContext CLR type alone, so without this, the model
    /// built (and cached) by whichever test runs first would be silently reused — converters and
    /// all — by every later test in the class, including ones whose own provider has since been
    /// disposed. Same fix already used by <c>DetectorTests.AutoEncryptionTestContext</c>.
    /// </summary>
    private sealed class DynamicModelCacheKeyFactory : Microsoft.EntityFrameworkCore.Infrastructure.IModelCacheKeyFactory
    {
        public object Create(DbContext context, bool designTime) => Guid.NewGuid();
    }

    public class AuditedDbContext : DbContext
    {
        private readonly IEncryptionCryptoProvider _provider;
        private readonly DecryptionAuditMaterializationInterceptor? _interceptor;

        public DbSet<AuditedCustomer> Customers => Set<AuditedCustomer>();

        public AuditedDbContext(DbContextOptions<AuditedDbContext> options, IEncryptionCryptoProvider provider, DecryptionAuditMaterializationInterceptor? interceptor)
            : base(options)
        {
            _provider = provider;
            _interceptor = interceptor;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.ReplaceService<Microsoft.EntityFrameworkCore.Infrastructure.IModelCacheKeyFactory, DynamicModelCacheKeyFactory>();

            if (_interceptor is not null)
            {
                optionsBuilder.AddInterceptors(_interceptor);
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.UseEncryption(_provider);
        }
    }

    private static AesGcmCryptoProvider MakeProvider() => new(AesGcmCryptoProvider.GenerateKey());

    /// <summary>
    /// The write context (no interceptor) and read context (with interceptor) in each test below
    /// are deliberately configured with different services, which gives EF Core's InMemory provider
    /// two different "internal service providers" under the hood. Without an explicit, shared
    /// <see cref="InMemoryDatabaseRoot"/>, each of those gets its own default root and therefore its
    /// own private store — same database name, but the read context would see zero rows even though
    /// the write context's SaveChangesAsync succeeded. Passing one shared root here is what makes
    /// the two contexts actually see the same data.
    /// </summary>
    private static DbContextOptions<AuditedDbContext> CreateDbOptions()
    {
        var root = new InMemoryDatabaseRoot();
        return new DbContextOptionsBuilder<AuditedDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString(), root)
            .Options;
    }

    [Fact]
    public async Task Interceptor_RaisesEvent_WithPropertyNameAndPrimaryKey_OnMaterializationOfNonNullEncryptedProperty()
    {
        using AesGcmCryptoProvider provider = MakeProvider();
        var sink = new RecordingSink();
        var trail = new DecryptionAuditTrail(new IDecryptionAuditSink[] { sink }, new DecryptionAuditTrailOptions(), EnterpriseGate(), NullLogger<DecryptionAuditTrail>.Instance);
        var interceptor = new DecryptionAuditMaterializationInterceptor(trail, new DecryptionAuditTrailOptions());

        var dbOptions = CreateDbOptions();

        using (var writeContext = new AuditedDbContext(dbOptions, provider, interceptor: null))
        {
            writeContext.Customers.Add(new AuditedCustomer { Id = 1, Ssn = "234-56-7890", Name = "Alex" });
            await writeContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        using (var readContext = new AuditedDbContext(dbOptions, provider, interceptor))
        {
            AuditedCustomer? customer = await readContext.Customers.FirstOrDefaultAsync(c => c.Id == 1, TestContext.Current.CancellationToken);
            Assert.NotNull(customer);
            Assert.Equal("234-56-7890", customer!.Ssn);
        }

        await trail.DrainOnceAsync(TestContext.Current.CancellationToken);

        DecryptionAuditEvent auditEvent = Assert.Single(sink.Events);
        Assert.Equal(nameof(AuditedCustomer), auditEvent.EntityType);
        Assert.Contains(nameof(AuditedCustomer.Ssn), auditEvent.PropertyNames);
        Assert.Equal("Id=1", auditEvent.PrimaryKey);
    }

    [Fact]
    public async Task Interceptor_RaisesNoEvent_WhenEncryptedPropertyIsNull()
    {
        using AesGcmCryptoProvider provider = MakeProvider();
        var sink = new RecordingSink();
        var trail = new DecryptionAuditTrail(new IDecryptionAuditSink[] { sink }, new DecryptionAuditTrailOptions(), EnterpriseGate(), NullLogger<DecryptionAuditTrail>.Instance);
        var interceptor = new DecryptionAuditMaterializationInterceptor(trail, new DecryptionAuditTrailOptions());

        var dbOptions = CreateDbOptions();

        using (var writeContext = new AuditedDbContext(dbOptions, provider, interceptor: null))
        {
            writeContext.Customers.Add(new AuditedCustomer { Id = 2, Ssn = null, Name = "NoSsn" });
            await writeContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        using (var readContext = new AuditedDbContext(dbOptions, provider, interceptor))
        {
            await readContext.Customers.FirstOrDefaultAsync(c => c.Id == 2, TestContext.Current.CancellationToken);
        }

        await trail.DrainOnceAsync(TestContext.Current.CancellationToken);

        Assert.Empty(sink.Events);
    }

    [Fact]
    public async Task Interceptor_IncludesAmbientContext_WhenSet()
    {
        using AesGcmCryptoProvider provider = MakeProvider();
        var sink = new RecordingSink();
        var trail = new DecryptionAuditTrail(new IDecryptionAuditSink[] { sink }, new DecryptionAuditTrailOptions(), EnterpriseGate(), NullLogger<DecryptionAuditTrail>.Instance);
        var interceptor = new DecryptionAuditMaterializationInterceptor(trail, new DecryptionAuditTrailOptions());

        var dbOptions = CreateDbOptions();

        using (var writeContext = new AuditedDbContext(dbOptions, provider, interceptor: null))
        {
            writeContext.Customers.Add(new AuditedCustomer { Id = 3, Ssn = "111-22-3333", Name = "Ctx" });
            await writeContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        DecryptionAuditContext.Current = new DecryptionAuditContext { UserId = "user-42", IpAddress = "10.0.0.1" };
        try
        {
            using var readContext = new AuditedDbContext(dbOptions, provider, interceptor);
            await readContext.Customers.FirstOrDefaultAsync(c => c.Id == 3, TestContext.Current.CancellationToken);
        }
        finally
        {
            DecryptionAuditContext.Current = null;
        }

        await trail.DrainOnceAsync(TestContext.Current.CancellationToken);

        DecryptionAuditEvent auditEvent = Assert.Single(sink.Events);
        Assert.Equal("user-42", auditEvent.UserId);
        Assert.Equal("10.0.0.1", auditEvent.IpAddress);
    }
}
