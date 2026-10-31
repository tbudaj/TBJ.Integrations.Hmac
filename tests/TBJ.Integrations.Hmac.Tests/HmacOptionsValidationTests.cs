using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace TBJ.Integrations.Hmac.Tests;

/// <summary>Testy walidacji opcji przy starcie — placeholder, za krótki sekret, puste pola.</summary>
public class HmacOptionsValidationTests
{
    private const string ValidSecret = "server-secret-0123456789abcdef0123456789";

    private static AuthenticationBuilder AuthBuilder()
        => new ServiceCollection().AddAuthentication();

    private static IHttpClientBuilder HttpBuilder()
        => new ServiceCollection().AddHttpClient("test");

    [Fact]
    public void Serwer_placeholder_sekretu_rzuca_przy_rejestracji()
    {
        var ex = Assert.Throws<OptionsValidationException>(() =>
            AuthBuilder().AddHmacAuthentication("test", o =>
                o.Clients.Add(new HmacClientCredentials { Kid = "k1", Secret = "<UZUPELNIC>" })));

        Assert.Contains("Clients[0]:Secret", ex.Message);
        Assert.Contains("<UZUPELNIC>", ex.Message);
    }

    [Fact]
    public void Serwer_krotki_sekret_rzuca_przy_rejestracji()
    {
        var ex = Assert.Throws<OptionsValidationException>(() =>
            AuthBuilder().AddHmacAuthentication("test", o =>
                o.Clients.Add(new HmacClientCredentials { Kid = "k1", Secret = "za-krotki" })));

        Assert.Contains("Clients[0]:Secret", ex.Message);
        Assert.Contains("32", ex.Message);
    }

    [Fact]
    public void Serwer_pusta_lista_klientow_rzuca_przy_rejestracji()
    {
        var ex = Assert.Throws<OptionsValidationException>(() =>
            AuthBuilder().AddHmacAuthentication("test", _ => { }));

        Assert.Contains("Clients", ex.Message);
    }

    [Fact]
    public void Serwer_pusty_kid_rzuca_przy_rejestracji()
    {
        var ex = Assert.Throws<OptionsValidationException>(() =>
            AuthBuilder().AddHmacAuthentication("test", o =>
                o.Clients.Add(new HmacClientCredentials { Secret = ValidSecret })));

        Assert.Contains("Clients[0]:Kid", ex.Message);
    }

    [Fact]
    public void Klient_placeholder_sekretu_rzuca_przy_rejestracji()
    {
        var ex = Assert.Throws<OptionsValidationException>(() =>
            HttpBuilder().AddHmacSigning(o =>
            {
                o.Kid = "k1";
                o.Secret = "<UZUPELNIC>";
            }));

        Assert.Contains("HmacSigning:Secret", ex.Message);
    }

    [Fact]
    public void Klient_krotki_sekret_rzuca_przy_rejestracji()
    {
        var ex = Assert.Throws<OptionsValidationException>(() =>
            HttpBuilder().AddHmacSigning(o =>
            {
                o.Kid = "k1";
                o.Secret = "12345";
            }));

        Assert.Contains("HmacSigning:Secret", ex.Message);
    }

    [Fact]
    public void Klient_pusty_kid_rzuca_przy_rejestracji()
    {
        var ex = Assert.Throws<OptionsValidationException>(() =>
            HttpBuilder().AddHmacSigning(o => o.Secret = ValidSecret));

        Assert.Contains("HmacSigning:Kid", ex.Message);
    }

    [Fact]
    public void Poprawna_konfiguracja_nie_rzuca()
    {
        AuthBuilder().AddHmacAuthentication("test", o =>
            o.Clients.Add(new HmacClientCredentials { Kid = "k1", Secret = ValidSecret }));

        HttpBuilder().AddHmacSigning(o =>
        {
            o.Kid = "k1";
            o.Secret = ValidSecret;
        });
    }
}
