using Microsoft.Extensions.Options;

namespace TBJ.Integrations.Hmac;

/// <summary>
/// <see cref="DelegatingHandler"/> podpisujący każde wychodzące żądanie HTTP schematem
/// <c>TBJ-INT-HMAC</c> — dołączany do <c>HttpClient</c> przez
/// <see cref="HmacExtensions"/> (<c>AddHmacSigning</c>).
/// </summary>
/// <remarks>
/// <para>
/// Handler buforuje treść żądania, liczy <c>bh</c>, dołącza nagłówek korelacji (jeśli żądanie
/// go nie ma, a skonfigurowany <see cref="HmacSigningOptions.CorrelationIdProvider"/> zwraca
/// wartość) oraz odczytuje tenanta z nagłówka żądania (ustawia go wywołujący — tenant wchodzi
/// do podpisu). Podpis budowany jest z bieżącym znacznikiem czasu, więc ponowienie żądania
/// przez politykę retry automatycznie dostaje nowy, ważny podpis.
/// </para>
/// </remarks>
public sealed class HmacSigningHandler : DelegatingHandler
{
    private readonly HmacSigningOptions options;
    private readonly TimeProvider timeProvider;

    /// <summary>Inicjalizuje handler z opcjami i źródłem czasu.</summary>
    public HmacSigningHandler(HmacSigningOptions options, TimeProvider? timeProvider = null)
    {
        this.options = options;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Inicjalizuje handler z opcji DI.</summary>
    public HmacSigningHandler(IOptions<HmacSigningOptions> options, TimeProvider timeProvider)
        : this(options.Value, timeProvider)
    {
    }

    /// <summary>Podpisuje żądanie i przekazuje je dalej w potoku handlerów.</summary>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await ReadBodyAsync(request, cancellationToken).ConfigureAwait(false);

        if (!request.Headers.Contains(options.CorrelationHeaderName))
        {
            var correlationId = options.CorrelationIdProvider?.Invoke();
            if (!string.IsNullOrEmpty(correlationId))
                request.Headers.TryAddWithoutValidation(options.CorrelationHeaderName, correlationId);
        }

        var tenant = request.Headers.TryGetValues(options.TenantHeaderName, out var tenantValues)
            ? tenantValues.FirstOrDefault()
            : null;

        var timestamp = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var pathAndQuery = request.RequestUri?.PathAndQuery ?? "/";
        var headerValue = HmacSignature.BuildAuthorizationHeader(
            options.Kid, options.Secret, timestamp, request.Method.Method, pathAndQuery, body, tenant);

        request.Headers.Remove("Authorization");
        request.Headers.TryAddWithoutValidation("Authorization", headerValue);

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Buforuje treść żądania i zwraca ją jako tablicę bajtów — brak treści traktowany jest
    /// jako pusty ciąg (<c>bh</c> liczony jest zawsze).
    /// </summary>
    private static async Task<byte[]> ReadBodyAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Content is null)
            return [];

        await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
        return await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }
}
