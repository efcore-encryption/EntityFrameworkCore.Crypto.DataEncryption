using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AesSample;

public class Address
{
    [CryptoEncrypted]
    public string Street { get; set; } = string.Empty;

    public string City { get; set; } = string.Empty;
}

public class UserEntity
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid Id { get; set; }

    [Required]
    public string FirstName { get; set; } = string.Empty;

    [Required]
    public string LastName { get; set; } = string.Empty;

    [Required]
    [CryptoEncrypted]
    public string Email { get; set; } = string.Empty;

    [Required]
    [CryptoEncrypted(CryptoStorageFormat.Binary)]
    public string Notes { get; set; } = string.Empty;

    [Required]
    [CryptoEncrypted]
    public byte[] EncryptedData { get; set; } = Array.Empty<byte>();

    [Required]
    [CryptoEncrypted(CryptoStorageFormat.Base64)]
    [Column(TypeName = "TEXT")]
    public byte[] EncryptedDataAsString { get; set; } = Array.Empty<byte>();

    // Numeric encryption (long and decimal)
    [CryptoEncrypted]
    [Column(TypeName = "TEXT")]
    public long? AccountNumber { get; set; }

    [CryptoEncrypted]
    [Column(TypeName = "TEXT")]
    public decimal Salary { get; set; }

    // Dictionary / Key-Value metadata encryption
    [CryptoEncrypted]
    [Column(TypeName = "TEXT")]
    public Dictionary<string, string>? Metadata { get; set; }

    // Owned Entity Type encryption
    public Address HomeAddress { get; set; } = new Address();
}
