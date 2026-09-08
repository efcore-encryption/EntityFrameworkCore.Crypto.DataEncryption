using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.DataEncryption;

namespace AesSample;

public class DatabaseContext : DbContext
{
    private readonly IEncryptionCryptoProvider _encryptionProvider;

    public DbSet<UserEntity> Users { get; set; }

    public DatabaseContext(DbContextOptions<DatabaseContext> options, IEncryptionCryptoProvider encryptionProvider)
        : base(options)
    {
        _encryptionProvider = encryptionProvider;
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserEntity>().OwnsOne(u => u.HomeAddress);

        modelBuilder.UseEncryption(_encryptionProvider);

        base.OnModelCreating(modelBuilder);
    }
}
