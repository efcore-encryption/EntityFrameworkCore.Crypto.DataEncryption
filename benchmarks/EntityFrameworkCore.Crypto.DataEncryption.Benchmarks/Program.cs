using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Microsoft.EntityFrameworkCore.DataEncryption;
using Microsoft.EntityFrameworkCore.DataEncryption.Providers;
using System.Security.Cryptography;

BenchmarkSwitcher.FromAssembly(typeof(EncryptionBenchmarks).Assembly).Run(args);

/// <summary>
/// Compares the legacy AES-CBC provider (static IV) with the AES-GCM provider
/// (random nonce + authentication tag) across representative payload sizes.
/// Run with: <c>dotnet run -c Release --project benchmarks/EntityFrameworkCore.Crypto.DataEncryption.Benchmarks</c>
/// </summary>
[MemoryDiagnoser]
[MarkdownExporterAttribute.GitHub]
public class EncryptionBenchmarks
{
    private IEncryptionCryptoProvider _cbc = null!;
    private AesGcmCryptoProvider _gcm = null!;
    private byte[] _plaintext = null!;
    private byte[] _cbcCiphertext = null!;
    private byte[] _gcmCiphertext = null!;

    /// <summary>Payload size in bytes: short field, typical row, document blob.</summary>
    [Params(64, 1024, 16_384)]
    public int PayloadSize { get; set; }

    /// <summary>Creates providers with fixed keys and pre-encrypts payloads for decrypt benchmarks.</summary>
    [GlobalSetup]
    public void Setup()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(iv);

        _cbc = new AesCryptoProvider(key, iv);
        _gcm = new AesGcmCryptoProvider(key);

        _plaintext = new byte[PayloadSize];
        RandomNumberGenerator.Fill(_plaintext);

        _cbcCiphertext = _cbc.Encrypt(_plaintext);
        _gcmCiphertext = _gcm.Encrypt(_plaintext);
    }

    /// <summary>Disposes the GCM key ring.</summary>
    [GlobalCleanup]
    public void Cleanup() => _gcm.Dispose();

    /// <summary>Baseline: AES-CBC encrypt.</summary>
    [Benchmark(Baseline = true)]
    public byte[] Cbc_Encrypt() => _cbc.Encrypt(_plaintext);

    /// <summary>AES-GCM encrypt (random nonce, tag computed).</summary>
    [Benchmark]
    public byte[] Gcm_Encrypt() => _gcm.Encrypt(_plaintext);

    /// <summary>AES-CBC decrypt.</summary>
    [Benchmark]
    public byte[] Cbc_Decrypt() => _cbc.Decrypt(_cbcCiphertext);

    /// <summary>AES-GCM decrypt (tag verified).</summary>
    [Benchmark]
    public byte[] Gcm_Decrypt() => _gcm.Decrypt(_gcmCiphertext);
}

/// <summary>
/// End-to-end row cost for the crypto layer: one "push" (encrypt) and one "pull" (decrypt)
/// of a realistic entity with five encrypted fields — Aadhaar (12 B), phone (13 B),
/// email (30 B), name (24 B), address (120 B) — plus one blind-index HMAC on the email.
/// Rows/second per core ≈ 1,000,000 / mean-µs reported by BenchmarkDotNet.
/// </summary>
[MemoryDiagnoser]
[MarkdownExporterAttribute.GitHub]
public class RowThroughputBenchmarks
{
    private AesGcmCryptoProvider _gcm = null!;
    private Microsoft.EntityFrameworkCore.DataEncryption.BlindIndex.BlindIndexHasher _hasher = null!;
    private byte[][] _plainFields = null!;
    private byte[][] _cipherFields = null!;

    /// <summary>Creates the provider, hasher, and one representative row.</summary>
    [GlobalSetup]
    public void Setup()
    {
        _gcm = new AesGcmCryptoProvider(AesGcmCryptoProvider.GenerateKey());
        _hasher = new Microsoft.EntityFrameworkCore.DataEncryption.BlindIndex.BlindIndexHasher(
            Microsoft.EntityFrameworkCore.DataEncryption.BlindIndex.BlindIndexHasher.GenerateKey());

        _plainFields =
        [
            System.Text.Encoding.UTF8.GetBytes("234567890124"),                  // Aadhaar
            System.Text.Encoding.UTF8.GetBytes("+91 98765 43210"),               // phone
            System.Text.Encoding.UTF8.GetBytes("priya.sharma@example.com"),      // email
            System.Text.Encoding.UTF8.GetBytes("Priya Venkatesan Sharma"),       // name
            System.Text.Encoding.UTF8.GetBytes("Flat 402, Sunshine Apartments, MG Road, Indiranagar, Bengaluru 560038, Karnataka, India"), // address
        ];

        _cipherFields = new byte[_plainFields.Length][];

        for (int i = 0; i < _plainFields.Length; i++)
        {
            _cipherFields[i] = _gcm.Encrypt(_plainFields[i]);
        }
    }

    /// <summary>Disposes the key ring.</summary>
    [GlobalCleanup]
    public void Cleanup() => _gcm.Dispose();

    /// <summary>Push path: encrypt all five fields of one row.</summary>
    [Benchmark(Baseline = true)]
    public int PushRow_Encrypt5Fields()
    {
        int total = 0;

        foreach (byte[] field in _plainFields)
        {
            total += _gcm.Encrypt(field).Length;
        }

        return total;
    }

    /// <summary>Push path with a blind index: five encrypts plus one HMAC on the email.</summary>
    [Benchmark]
    public int PushRow_Encrypt5Fields_Plus1BlindIndex()
    {
        int total = 0;

        foreach (byte[] field in _plainFields)
        {
            total += _gcm.Encrypt(field).Length;
        }

        return total + (_hasher.Compute("priya.sharma@example.com")?.Length ?? 0);
    }

    /// <summary>Pull path: decrypt all five fields of one row.</summary>
    [Benchmark]
    public int PullRow_Decrypt5Fields()
    {
        int total = 0;

        foreach (byte[] field in _cipherFields)
        {
            total += _gcm.Decrypt(field).Length;
        }

        return total;
    }
}
