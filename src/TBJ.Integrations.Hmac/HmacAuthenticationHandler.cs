using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TBJ.Integrations.Hmac;

/// <summary>
/// Handler uwierzytelniania ASP.NET Core weryfikujący żądania podpisane schematem
/// <c>TBJ-INT-HMAC</c> przez <see cref="HmacRequestVerifier"/>.
/// </summary>
/// <remarks>
/// <para>
/// Handler buforuje treść żądania (<c>EnableBuffering()</c>),
/// żeby móc policzyć <c>bh</c> i nadal przekazać treść dalej w pipeline. Brak nagłówka
/// <c>Authorization</c> tego schematu daje <c>NoResult</c> (żądanie może obsłużyć inny schemat).
/// </para>
/// <para>
/// Po pomyślnym uwierzytelnieniu principal zawiera claim tenanta (<see cref="HmacServerOptions.TenantClaimType"/>)
/// i klienta (<see cref="HmacServerOptions.ClientClaimType"/> = <c>kid</c>).
/// Odpowiedź <c>403</c> zamiast <c>401</c> zwracana jest wyłącznie przy
/// <see cref="HmacVerificationFailure.TenantNotAllowed"/>.
/// </para>
/// </remarks>
public sealed class HmacAuthenticationHandler : AuthenticationHandler<HmacServerOptions>
{
    private const string FailureContextItemKey = "TBJ.Integrations.Hmac.Failure";

    private readonly IMemoryCache replayCache;
    private readonly TimeProvider timeProvider;

    /// <summary>Inicjalizuje handler z zależnościami wstrzykiwanymi z DI.</summary>
    public HmacAuthenticationHandler(
        IOptionsMonitor<HmacServerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IMemoryCache replayCache,
        TimeProvider timeProvider)
        : base(options, logger, encoder)
    {
        this.replayCache = replayCache;
        this.timeProvider = timeProvider;
    }

    /// <summary>Weryfikuje nagłówek <c>Authorization</c> bieżącego żądania.</summary>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorizationHeader = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorizationHeader)
            || !authorizationHeader.StartsWith(HmacSignature.SchemeName + " ", StringComparison.Ordinal))
        {
            // Brak naszego schematu — żądanie może obsłużyć inny schemat uwierzytelniania.
            return AuthenticateResult.NoResult();
        }

        var bodyResult = await ReadBodyAsync().ConfigureAwait(false);
        if (bodyResult.TooLarge)
        {
            Logger.LogWarning(
                "Odrzucono żądanie {Scheme}: treść przekracza limit {MaxBodyBytes} bajtów.",
                HmacSignature.SchemeName, Options.MaxBodyBytes);
            Context.Items[FailureContextItemKey] = HmacVerificationFailure.MalformedHeader;
            return AuthenticateResult.Fail("Treść żądania przekracza dozwolony rozmiar.");
        }

        var tenant = Request.Headers[Options.TenantHeaderName].ToString();
        var tenantValue = string.IsNullOrEmpty(tenant) ? null : tenant;

        // Ścieżka w formie drutowej — dokładnie tak, jak trafiła na serwer; klient podpisuje
        // RequestUri.PathAndQuery, więc obie strony muszą operować na formie percent-encoded.
        var pathAndQuery = Request.PathBase.ToUriComponent()
            + Request.Path.ToUriComponent()
            + Request.QueryString.ToUriComponent();

        var verifier = new HmacRequestVerifier(Options, replayCache, timeProvider);
        var result = verifier.Verify(authorizationHeader, Request.Method, pathAndQuery, bodyResult.Body, tenantValue);

        if (!result.Succeeded)
        {
            Logger.LogWarning(
                "Odrzucono żądanie {Scheme}: przyczyna {Failure}, kid {Kid}, tenant {Tenant}.",
                HmacSignature.SchemeName, result.Failure, result.Kid ?? "-", result.Tenant ?? "-");
            Context.Items[FailureContextItemKey] = result.Failure;
            return AuthenticateResult.Fail($"Weryfikacja {HmacSignature.SchemeName} nie powiodła: {result.Failure}.");
        }

        var claims = new List<Claim>
        {
            new(Options.ClientClaimType, result.Kid!),
        };
        if (result.Tenant is not null)
            claims.Add(new Claim(Options.TenantClaimType, result.Tenant));

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    /// <summary>
    /// Zwraca <c>403</c>, gdy odrzucenie wynikało z niedozwolonego tenanta; w pozostałych
    /// przypadkach <c>401</c> z nagłówkiem <c>WWW-Authenticate: TBJ-INT-HMAC</c>.
    /// </summary>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (Context.Items.TryGetValue(FailureContextItemKey, out var failure)
            && failure is HmacVerificationFailure.TenantNotAllowed)
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = HmacSignature.SchemeName;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Buforuje i odczytuje treść żądania z limitem <see cref="HmacServerOptions.MaxBodyBytes"/>,
    /// po czym przewija strumień na początek dla kolejnych etapów pipeline'u.
    /// </summary>
    private async Task<(byte[] Body, bool TooLarge)> ReadBodyAsync()
    {
        Request.EnableBuffering();

        if (Request.ContentLength > Options.MaxBodyBytes)
            return (Array.Empty<byte>(), true);

        using var buffer = new MemoryStream();
        var chunk = new byte[64 * 1024];
        int read;
        while ((read = await Request.Body.ReadAsync(chunk, Request.HttpContext.RequestAborted).ConfigureAwait(false)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > Options.MaxBodyBytes)
            {
                Request.Body.Position = 0;
                return (Array.Empty<byte>(), true);
            }
        }

        Request.Body.Position = 0;
        return (buffer.ToArray(), false);
    }
}
