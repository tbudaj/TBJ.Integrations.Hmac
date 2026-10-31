using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Moq;

namespace TBJ.Integrations.Hmac.Tests;

/// <summary>Testy weryfikatora żądań — każda przyczyna odrzucenia, rotacja, replay, tolerancja czasu.</summary>
public class HmacRequestVerifierTests
{
    private const string Kid = "svc-a";
    private const string Secret = "server-secret-0123456789abcdef0123456789";
    private const string Tenant = "S-100";
    private const int ToleranceSeconds = 300;
    private const string Path = "/api/test?x=1";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1767225600);
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"a\":1}");

    private static HmacClientCredentials Client(string secret = Secret, string kid = Kid, params string[] tenants)
        => new() { Kid = kid, Secret = secret, AllowedTenants = tenants.Length > 0 ? tenants.ToList() : new List<string> { Tenant } };

    private static HmacRequestVerifier Verifier(TimeProvider time, IMemoryCache cache, params HmacClientCredentials[] clients)
        => new(clients, ToleranceSeconds, cache, time);

    private static TimeProvider FixedTime(DateTimeOffset? at = null)
    {
        var mock = new Mock<TimeProvider>();
        mock.Setup(t => t.GetUtcNow()).Returns(at ?? Now);
        return mock.Object;
    }

    private static string Sign(string secret = Secret, long? ts = null, string method = "POST",
        string path = Path, byte[]? body = null, string? tenant = Tenant, string kid = Kid)
        => HmacSignature.BuildAuthorizationHeader(kid, secret, ts ?? Now.ToUnixTimeSeconds(), method, path, body ?? Body, tenant);

    [Fact]
    public void Poprawne_zadanie_przechodzi_i_zwraca_kid_oraz_tenanta()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(), "POST", Path, Body, Tenant);

        Assert.True(result.Succeeded);
        Assert.Equal(HmacVerificationFailure.None, result.Failure);
        Assert.Equal(Kid, result.Kid);
        Assert.Equal(Tenant, result.Tenant);
    }

    [Fact]
    public void Brak_naglowka_daje_MissingHeader()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(null, "POST", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.MissingHeader, result.Failure);
    }

    [Theory]
    [InlineData("Bearer abc")]
    [InlineData("TBJ-INT-HMAC ts=1")]
    public void Niemozliwy_do_sparsowania_naglowek_daje_MalformedHeader(string header)
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(header, "POST", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.MalformedHeader, result.Failure);
    }

    [Fact]
    public void Nieobslugiwana_wersja_daje_UnsupportedVersion()
    {
        var header = Sign().Replace("v=1", "v=2");
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(header, "POST", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.UnsupportedVersion, result.Failure);
    }

    [Fact]
    public void Nieznany_kid_daje_UnknownKid()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(kid: "inny"), "POST", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.UnknownKid, result.Failure);
    }

    [Theory]
    [InlineData(-ToleranceSeconds - 1)]
    [InlineData(ToleranceSeconds + 1)]
    public void Znacznik_czasu_poza_oknem_daje_TimestampOutOfRange(long offsetSeconds)
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(ts: Now.ToUnixTimeSeconds() + offsetSeconds), "POST", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.TimestampOutOfRange, result.Failure);
    }

    [Theory]
    [InlineData(-ToleranceSeconds)]
    [InlineData(ToleranceSeconds - 1)]
    public void Znacznik_czasu_w_obrebie_okna_przechodzi(long offsetSeconds)
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(ts: Now.ToUnixTimeSeconds() + offsetSeconds), "POST", Path, Body, Tenant);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Zmieniona_tresc_daje_BodyHashMismatch()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(), "POST", Path, Encoding.UTF8.GetBytes("{\"a\":2}"), Tenant);

        Assert.Equal(HmacVerificationFailure.BodyHashMismatch, result.Failure);
    }

    [Fact]
    public void Zly_sekret_daje_InvalidSignature()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(secret: "inny-sekret-0123456789abcdef0123456789"), "POST", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.InvalidSignature, result.Failure);
    }

    [Fact]
    public void Zmieniona_metoda_daje_InvalidSignature()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(), "GET", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.InvalidSignature, result.Failure);
    }

    [Fact]
    public void Zmieniona_sciezka_daje_InvalidSignature()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(), "POST", "/api/inna?x=1", Body, Tenant);

        Assert.Equal(HmacVerificationFailure.InvalidSignature, result.Failure);
    }

    [Fact]
    public void Podmieniony_tenant_daje_InvalidSignature()
    {
        // Tenant wchodzi do ciągu kanonicznego — podpis pod S-100 nie zgadza się dla S-200.
        var client = Client(tenants: [Tenant, "S-200"]);
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), client)
            .Verify(Sign(), "POST", Path, Body, "S-200");

        Assert.Equal(HmacVerificationFailure.InvalidSignature, result.Failure);
    }

    [Fact]
    public void Brak_tenanta_daje_MissingTenant()
    {
        // Podpis zbudowany z pustym tenantem jest poprawny — odrzuca dopiero kontrola tenanta.
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(tenant: null), "POST", Path, Body, null);

        Assert.Equal(HmacVerificationFailure.MissingTenant, result.Failure);
    }

    [Fact]
    public void Tenant_spoza_listy_daje_TenantNotAllowed()
    {
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(Sign(tenant: "S-999"), "POST", Path, Body, "S-999");

        Assert.Equal(HmacVerificationFailure.TenantNotAllowed, result.Failure);
    }

    [Fact]
    public void Pusta_lista_dozwolonych_tenantow_odmawia_kazdemu()
    {
        var client = new HmacClientCredentials { Kid = Kid, Secret = Secret }; // AllowedTenants puste
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), client)
            .Verify(Sign(), "POST", Path, Body, Tenant);

        Assert.Equal(HmacVerificationFailure.TenantNotAllowed, result.Failure);
    }

    [Fact]
    public void Powtorzone_zadanie_daje_Replay()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var verifier = Verifier(FixedTime(), cache, Client());
        var header = Sign();

        Assert.True(verifier.Verify(header, "POST", Path, Body, Tenant).Succeeded);
        Assert.Equal(HmacVerificationFailure.Replay,
            verifier.Verify(header, "POST", Path, Body, Tenant).Failure);
    }

    [Fact]
    public void Rotacja_sekretow_dowolny_sekret_dla_kid_przechodzi()
    {
        var clients = new[]
        {
            Client(secret: "stary-sekret-0123456789abcdef0123456789"),
            Client(secret: "nowy-sekret-0123456789abcdef0123456789a"),
        };
        var verifier = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), clients);

        Assert.True(verifier.Verify(
            Sign(secret: "nowy-sekret-0123456789abcdef0123456789a"), "POST", Path, Body, Tenant).Succeeded);
    }

    [Fact]
    public void Zadanie_GET_z_pusta_trescia_przechodzi()
    {
        var header = Sign(method: "GET", path: "/api/lista", body: []);
        var result = Verifier(FixedTime(), new MemoryCache(new MemoryCacheOptions()), Client())
            .Verify(header, "GET", "/api/lista", ReadOnlySpan<byte>.Empty, Tenant);

        Assert.True(result.Succeeded);
    }
}
