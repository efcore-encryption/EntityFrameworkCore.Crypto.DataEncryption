using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.DataEncryption.Providers;
using System;
using System.Collections.Generic;
using System.Linq;

namespace AesSample;

static class Program
{
    static void Main()
    {
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        var options = new DbContextOptionsBuilder<DatabaseContext>()
            .UseSqlite(connection)
            .Options;

        // AES key randomly generated at each run.
        CryptoAesKeyInfo keyInfo = AesCryptoProvider.GenerateKey(CryptoAesKeySize.AES256Bits);
        byte[] encryptionKey = keyInfo.Key;
        byte[] encryptionIV = keyInfo.IV;
        var encryptionProvider = new AesCryptoProvider(encryptionKey, encryptionIV);

        using (var context = new DatabaseContext(options, encryptionProvider))
        {
            context.Database.EnsureCreated();

            var user = new UserEntity
            {
                FirstName = "efcore",
                LastName = "encryption",
                Email = "sales@email.com",
                Notes = "Hello world!",
                EncryptedData = new byte[2] { 1, 2 },
                EncryptedDataAsString = new byte[2] { 3, 4 },
                AccountNumber = 98765432109876L,
                Salary = 125000.50M,
                Metadata = new Dictionary<string, string>
                {
                    ["Role"] = "Security Officer",
                    ["SecurityClearance"] = "TopSecret-Level5"
                },
                HomeAddress = new Address
                {
                    Street = "123 Encrypted Way",
                    City = "Metropolis"
                }
            };

            context.Users.Add(user);
            context.SaveChanges();

            Console.WriteLine($"[✓] Saved user with encrypted string, byte[], numeric (long/decimal), Dictionary, and Owned Entity types.");
            Console.WriteLine($"Users count: {context.Users.Count()}");
        }

        using (var context = new DatabaseContext(options, encryptionProvider))
        {
            UserEntity user = context.Users.First();

            Console.WriteLine($"[✓] Loaded & Decrypted User:");
            Console.WriteLine($"  - Name: {user.FirstName} {user.LastName}");
            Console.WriteLine($"  - Email (Encrypted string): {user.Email}");
            Console.WriteLine($"  - AccountNumber (Encrypted long): {user.AccountNumber}");
            Console.WriteLine($"  - Salary (Encrypted decimal): ${user.Salary:N2}");
            Console.WriteLine($"  - Metadata (Encrypted Dictionary): Role={user.Metadata?["Role"]}, Clearance={user.Metadata?["SecurityClearance"]}");
            Console.WriteLine($"  - Address (Owned Entity): Street={user.HomeAddress.Street} (Encrypted), City={user.HomeAddress.City} (Plaintext)");
        }
    }
}
