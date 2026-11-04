using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace TBJ.Integrations.Hmac.Tests;

/// <summary>
/// Testy end-to-end: klient z <c>AddHmacSigning</c> → serwer TestServer z
/// <c>AddHmacAuthentication</c> i endpointem chronionym <c>[Authorize]</c>.
/// </summary>
public class HmacEndToEndTests
{
    private const string Scheme = "tbj-hmac-test";
    private const string Kid = "svc-a";
    private const string Secret = "server-secret-0123456789abcdef0123456789";
    private const string Tenant = "S-100";

    private static IHost CreateServer(long? cacheSizeLimit = null)
    {
        var builder = new HostBuilder()
            .ConfigureWebHost(webHost => webHost
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                if (cacheSizeLimit is not null)
                    services.AddMemoryCache(o => o.SizeLimit = cacheSizeLimit.Value);
                services.AddAuthentication(Scheme)
                    .AddHmacAuthentication(Scheme, options =>
                    {
                        options.Clients.Add(new HmacClientCredentials
                        {
                            Kid = Kid,
                            Secret = Secret,
                            AllowedTenants = { Tenant },
                        });
                    });
                services.AddAuthorization();
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    // Endpoint zwraca claimy principalu — pozwala zweryfikować mapowanie kid/tenanta.
                    endpoints.MapGet("/secure", (HttpContext ctx) => Results.Json(new
                    {
                        Sid = ctx.User.FindFirst("Sid")?.Value,
                        Client = ctx.User.FindFirst("IntegrationClient")?.Value,
                    })).RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = Scheme });

                    endpoints.MapPost("/echo", async (HttpContext ctx) =>
                    {
                        using var reader = new StreamReader(ctx.Request.Body);
                        var body = await reader.ReadToEndAsync();
                        await ctx.Response.WriteAsJsonAsync(new { Received = body });
                    }).RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = Scheme });
                });
            }));

        return builder.Start();
    }

    private static HttpClient CreateSignedClient(IHost server, string secret = Secret, string kid = Kid)
    {
        var services = new ServiceCollection();
        services.AddHttpClient("signed")
            .ConfigurePrimaryHttpMessageHandler(_ => server.GetTestServer().CreateHandler())
            .AddHmacSigning(options =>
            {
                options.Kid = kid;
                options.Secret = secret;
                options.CorrelationIdProvider = () => "corr-123";
            });
        var provider = services.BuildServiceProvider();

        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("signed");
        client.BaseAddress = server.GetTestServer().BaseAddress;
        return client;
    }

    private static HttpRequestMessage SignedRequest(HttpMethod method, string url, string tenant = Tenant, HttpContent? content = null)
    {
        var request = new HttpRequestMessage(method, url) { Content = content };
        request.Headers.Add("X-Sid", tenant);
        return request;
    }

    [Fact]
    public async Task Podpisane_zadanie_daje_200_i_prawidlowe_claime()
    {
        using var server = CreateServer();
        using var client = CreateSignedClient(server);

        var response = await client.SendAsync(SignedRequest(HttpMethod.Get, "/secure"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Tenant, json.RootElement.GetProperty("sid").GetString());
        Assert.Equal(Kid, json.RootElement.GetProperty("client").GetString());
    }

    [Fact]
    public async Task Podpisane_zadanie_przechodzi_przy_globalnym_SizeLimit_cache()
    {
        // Wspólny IMemoryCache hosta z SizeLimit (np. przez AddNfzUmwApi) — wpis
        // anty-replay weryfikatora ma Size=1, więc podpisane żądanie daje 200.
        using var server = CreateServer(cacheSizeLimit: 10);
        using var client = CreateSignedClient(server);

        var response = await client.SendAsync(SignedRequest(HttpMethod.Get, "/secure"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Zly_sekret_daje_401()
    {
        using var server = CreateServer();
        using var client = CreateSignedClient(server, secret: "inny-sekret-0123456789abcdef0123456789");

        var response = await client.SendAsync(SignedRequest(HttpMethod.Get, "/secure"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Tenant_spoza_listy_daje_403()
    {
        using var server = CreateServer();
        using var client = CreateSignedClient(server);

        var response = await client.SendAsync(SignedRequest(HttpMethod.Get, "/secure", tenant: "S-999"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Brak_naglowka_daje_401_i_WWWAuthenticate()
    {
        using var server = CreateServer();
        using var client = server.GetTestClient();

        var response = await client.GetAsync("/secure");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate,
            h => h.Scheme == HmacSignature.SchemeName);
    }

    [Fact]
    public async Task POST_z_trescia_json_przechodzi_i_tresc_dociera_do_endpointu()
    {
        using var server = CreateServer();
        using var client = CreateSignedClient(server);

        var content = new StringContent("{\"nazwa\":\"test\"}", Encoding.UTF8, "application/json");
        var response = await client.SendAsync(SignedRequest(HttpMethod.Post, "/echo", content: content));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("{\"nazwa\":\"test\"}", json.RootElement.GetProperty("received").GetString());
    }

    [Fact]
    public async Task GET_z_query_ze_spacja_i_polskimi_literami_przechodzi()
    {
        using var server = CreateServer();
        using var client = CreateSignedClient(server);

        // Scieżka drutowa po obu stronach musi być identyczna: klient podpisuje
        // RequestUri.PathAndQuery, serwer odtwarza PathBase+Path+QueryString.ToUriComponent().
        var response = await client.SendAsync(
            SignedRequest(HttpMethod.Get, "/secure?imie=Jan Kowalski&miasto=Łódź"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Dwa_klienci_z_roznymi_poswiadczeniami_podpisuja_wlasnymi_danymi()
    {
        // Opcje nazwane nazwą klienta — każdy HttpClient ma własne kid/sekret.
        var captured = new Dictionary<string, string>();
        var services = new ServiceCollection();
        services.AddHttpClient("klient-a")
            .ConfigurePrimaryHttpMessageHandler(_ => new RecordingHandler("a", captured))
            .AddHmacSigning(o => { o.Kid = "kid-a"; o.Secret = "sekret-a-0123456789abcdef0123456789"; });
        services.AddHttpClient("klient-b")
            .ConfigurePrimaryHttpMessageHandler(_ => new RecordingHandler("b", captured))
            .AddHmacSigning(o => { o.Kid = "kid-b"; o.Secret = "sekret-b-0123456789abcdef0123456789"; });
        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();

        var clientA = factory.CreateClient("klient-a");
        clientA.BaseAddress = new Uri("http://localhost/");
        var clientB = factory.CreateClient("klient-b");
        clientB.BaseAddress = new Uri("http://localhost/");

        await clientA.SendAsync(SignedRequest(HttpMethod.Get, "/secure"));
        await clientB.SendAsync(SignedRequest(HttpMethod.Get, "/secure"));

        Assert.True(HmacSignature.TryParse(captured["a"], out var tokenA));
        Assert.True(HmacSignature.TryParse(captured["b"], out var tokenB));
        Assert.Equal("kid-a", tokenA.Kid);
        Assert.Equal("kid-b", tokenB.Kid);

        // Podpis klienta A zgadza się z jego sekretem, a nie z sekretem klienta B.
        var canonical = HmacSignature.BuildCanonical(
            tokenA.Timestamp, "GET", "/secure", tokenA.BodyHash, Tenant);
        Assert.True(HmacSignature.FixedTimeEqualsBase64Url(
            HmacSignature.ComputeSignature("sekret-a-0123456789abcdef0123456789", canonical), tokenA.Signature));
        Assert.False(HmacSignature.FixedTimeEqualsBase64Url(
            HmacSignature.ComputeSignature("sekret-b-0123456789abcdef0123456789", canonical), tokenA.Signature));
    }

    /// <summary>Handler rejestrujący nagłówek Authorization pod kluczem i zwracający 200.</summary>
    private sealed class RecordingHandler(string key, IDictionary<string, string> captured) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            captured[key] = request.Headers.Authorization?.ToString() ?? string.Empty;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    [Fact]
    public async Task Handler_dodaje_naglowek_korelacji_gdy_go_brak()
    {
        using var server = CreateServer();
        using var signingHandler = new HmacSigningHandler(new HmacSigningOptions
        {
            Kid = Kid,
            Secret = Secret,
            CorrelationIdProvider = () => "corr-123",
        })
        { InnerHandler = server.GetTestServer().CreateHandler() };
        using var client = new HttpClient(signingHandler) { BaseAddress = server.GetTestServer().BaseAddress };

        var request = SignedRequest(HttpMethod.Get, "/secure");
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("corr-123", request.Headers.GetValues("X-Correlation-Id").Single());
    }
}
