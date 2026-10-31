using System.Text;

namespace TBJ.Integrations.Hmac.Tests;

/// <summary>Testy algorytmu podpisu — ciąg kanoniczny, hash treści, format nagłówka, parser.</summary>
public class HmacSignatureTests
{
    private const string Secret = "test-secret-0123456789abcdef0123456789";
    private const long Timestamp = 1767225600; // 2026-01-01T00:00:00Z

    [Fact]
    public void BuildCanonical_sklada_pola_zgodnie_z_protokolem_v1()
    {
        var canonical = HmacSignature.BuildCanonical(
            Timestamp, "post", "/api/test?x=1&y=2", "bh-value", "S100");

        // Metoda normalizowana do wielkich liter, brakujący tenant = pusty ostatni wiersz.
        Assert.Equal("v1\n1767225600\nPOST\n/api/test?x=1&y=2\nbh-value\nS100", canonical);
        Assert.Equal("v1\n1767225600\nPOST\n/api/test?x=1&y=2\nbh-value\n",
            HmacSignature.BuildCanonical(Timestamp, "POST", "/api/test?x=1&y=2", "bh-value", null));
    }

    [Fact]
    public void ComputeBodyHash_pusta_tresc_daje_sha256_pustego_ciagu()
    {
        // Znana wartość SHA-256("") w Base64Url — policzona niezależnie (PowerShell).
        Assert.Equal("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            HmacSignature.ComputeBodyHash(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void ComputeBodyHash_dla_abc_zgodna_z_niezaleznym_obliczeniem()
    {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
        Assert.Equal("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
            HmacSignature.ComputeBodyHash(Encoding.UTF8.GetBytes("abc")));
    }

    [Fact]
    public void ComputeSignature_zgodna_z_wektorem_testowym()
    {
        // Wektor policzony niezależnie w PowerShell (System.Security.Cryptography.HMACSHA256):
        //   klucz  = UTF8(Secret)
        //   dane   = UTF8("v1\n1767225600\nPOST\n/api/test?x=1&y=2\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\nS100")
        //   wynik  = Base64Url(HMAC-SHA256) = eios-Uie1QAVCGGXW4OjflRPSkpI4A9TEi9pzYZ9Xec
        var canonical = "v1\n1767225600\nPOST\n/api/test?x=1&y=2\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\nS100";

        Assert.Equal("eios-Uie1QAVCGGXW4OjflRPSkpI4A9TEi9pzYZ9Xec",
            HmacSignature.ComputeSignature(Secret, canonical));
    }

    [Fact]
    public void BuildAuthorizationHeader_kompletny_naglowek_z_wektorem()
    {
        var header = HmacSignature.BuildAuthorizationHeader(
            "k1", Secret, Timestamp, "POST", "/api/test?x=1&y=2", ReadOnlySpan<byte>.Empty, "S100");

        Assert.Equal(
            "TBJ-INT-HMAC v=1;ts=1767225600;kid=k1;bh=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU;sig=eios-Uie1QAVCGGXW4OjflRPSkpI4A9TEi9pzYZ9Xec",
            header);
    }

    [Fact]
    public void TryParse_odtwarza_wszystkie_atrybuty()
    {
        var header = HmacSignature.BuildAuthorizationHeader(
            "k1", Secret, Timestamp, "GET", "/api/x", ReadOnlySpan<byte>.Empty, "S1");

        Assert.True(HmacSignature.TryParse(header, out var token));
        Assert.Equal(1, token.Version);
        Assert.Equal(Timestamp, token.Timestamp);
        Assert.Equal("k1", token.Kid);
        Assert.Equal("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", token.BodyHash);
        Assert.False(string.IsNullOrEmpty(token.Signature));
    }

    [Fact]
    public void TryParse_toleruje_nieznane_atrybuty()
    {
        var header = "TBJ-INT-HMAC v=1;ts=1767225600;kid=k1;extra=cos;bh=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU;sig=abc;inne=1";

        Assert.True(HmacSignature.TryParse(header, out var token));
        Assert.Equal("k1", token.Kid);
        Assert.Equal("abc", token.Signature);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Bearer abc")]                        // inny schemat
    [InlineData("TBJ-INT-HMAC")]                      // brak atrybutów
    [InlineData("TBJ-INT-HMAC v=1;ts=1;kid=k")]       // brak bh i sig
    [InlineData("TBJ-INT-HMAC v=x;ts=1;kid=k;bh=b;sig=s")] // v nie jest liczbą
    [InlineData("TBJ-INT-HMAC v=1;ts=x;kid=k;bh=b;sig=s")] // ts nie jest liczbą
    public void TryParse_odrzuca_niepoprawne_naglowki(string? header)
    {
        Assert.False(HmacSignature.TryParse(header, out _));
    }
}
