using Microsoft.Extensions.Caching.Memory;

namespace TBJ.Integrations.Hmac;

/// <summary>
/// Weryfikator żądań <c>TBJ-INT-HMAC</c> niezależny od ASP.NET Core — przyjmuje surowe składniki
/// żądania (nagłówek, metoda, ścieżka, treść, tenant) i zwraca wynik z przyczyną odrzucenia.
/// Używany przez <see cref="HmacAuthenticationHandler"/>, może też służyć poza pipeline'em HTTP.
/// </summary>
/// <remarks>
/// Kolejność kontroli: parsowanie nagłówka → wersja protokołu → klient po <c>kid</c> → okno czasu
/// → zgodność <c>bh</c> z treścią → podpis (dowolny sekret z danym <c>kid</c> — rotacja) → tenant
/// → ochrona przed powtórzeniem (replay) na końcu, tylko po poprawnym podpisie.
/// </remarks>
public sealed class HmacRequestVerifier
{
    private readonly IReadOnlyList<HmacClientCredentials> clients;
    private readonly TimeSpan timestampTolerance;
    private readonly IMemoryCache replayCache;
    private readonly TimeProvider timeProvider;

    /// <summary>
    /// Inicjalizuje weryfikator z listą znanych klientów i oknem tolerancji zegara.
    /// </summary>
    /// <param name="clients">Skonfigurowane poświadczenia klientów (wpisy z tym samym <c>Kid</c> = rotacja).</param>
    /// <param name="timestampToleranceSeconds">Dopuszczalne odchylenie znacznika czasu w sekundach.</param>
    /// <param name="replayCache">Pamięć podręczna używana do wykrywania powtórzeń żądań.</param>
    /// <param name="timeProvider">Źródło czasu — jawny parametr dla testowalności.</param>
    public HmacRequestVerifier(
        IEnumerable<HmacClientCredentials> clients,
        int timestampToleranceSeconds,
        IMemoryCache replayCache,
        TimeProvider timeProvider)
    {
        this.clients = clients.ToList();
        this.timestampTolerance = TimeSpan.FromSeconds(timestampToleranceSeconds);
        this.replayCache = replayCache;
        this.timeProvider = timeProvider;
    }

    /// <summary>
    /// Inicjalizuje weryfikator ustawieniami z opcji serwera.
    /// </summary>
    public HmacRequestVerifier(HmacServerOptions options, IMemoryCache replayCache, TimeProvider timeProvider)
        : this(options.Clients, options.TimestampToleranceSeconds, replayCache, timeProvider)
    {
    }

    /// <summary>
    /// Weryfikuje żądanie względem skonfigurowanych klientów.
    /// </summary>
    /// <param name="authorizationHeader">Surowa wartość nagłówka <c>Authorization</c> (może być <c>null</c>).</param>
    /// <param name="method">Metoda HTTP żądania.</param>
    /// <param name="pathAndQuery">Ścieżka wraz z query w formie drutowej (percent-encoded).</param>
    /// <param name="body">Surowa treść żądania (może być pusta).</param>
    /// <param name="tenant">Wartość nagłówka tenanta (może być <c>null</c>).</param>
    public HmacVerificationResult Verify(
        string? authorizationHeader, string method, string pathAndQuery, ReadOnlySpan<byte> body, string? tenant)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader))
            return HmacVerificationResult.Fail(HmacVerificationFailure.MissingHeader, null, tenant);

        if (!HmacSignature.TryParse(authorizationHeader, out var token))
            return HmacVerificationResult.Fail(HmacVerificationFailure.MalformedHeader, null, tenant);

        if (token.Version != HmacSignature.ProtocolVersion)
            return HmacVerificationResult.Fail(HmacVerificationFailure.UnsupportedVersion, token.Kid, tenant);

        var matchingClients = clients
            .Where(c => string.Equals(c.Kid, token.Kid, StringComparison.Ordinal))
            .ToList();
        if (matchingClients.Count == 0)
            return HmacVerificationResult.Fail(HmacVerificationFailure.UnknownKid, token.Kid, tenant);

        var tokenTime = DateTimeOffset.FromUnixTimeSeconds(token.Timestamp);
        if ((tokenTime - timeProvider.GetUtcNow()).Duration() > timestampTolerance)
            return HmacVerificationResult.Fail(HmacVerificationFailure.TimestampOutOfRange, token.Kid, tenant);

        var actualBodyHash = HmacSignature.ComputeBodyHash(body);
        if (!HmacSignature.FixedTimeEqualsBase64Url(actualBodyHash, token.BodyHash))
            return HmacVerificationResult.Fail(HmacVerificationFailure.BodyHashMismatch, token.Kid, tenant);

        var canonical = HmacSignature.BuildCanonical(
            token.Timestamp, method, pathAndQuery, token.BodyHash, tenant);

        // Rotacja sekretów — akceptujemy podpis zgodny z dowolnym sekretem przypisanym do kid.
        var signatureValid = matchingClients.Any(c =>
            HmacSignature.FixedTimeEqualsBase64Url(HmacSignature.ComputeSignature(c.Secret, canonical), token.Signature));
        if (!signatureValid)
            return HmacVerificationResult.Fail(HmacVerificationFailure.InvalidSignature, token.Kid, tenant);

        if (string.IsNullOrEmpty(tenant))
            return HmacVerificationResult.Fail(HmacVerificationFailure.MissingTenant, token.Kid, tenant);

        // Dozwoleni tenanci to suma list wszystkich wpisów o danym kid (rotacja sekretów
        // nie może zmieniać zbioru dozwolonych tenantów).
        var allowedTenants = matchingClients.SelectMany(c => c.AllowedTenants).ToHashSet(StringComparer.Ordinal);
        if (allowedTenants.Count == 0 || !allowedTenants.Contains(tenant))
            return HmacVerificationResult.Fail(HmacVerificationFailure.TenantNotAllowed, token.Kid, tenant);

        // Ochrona przed powtórzeniem — dopiero po poprawnym podpisie, żeby obcy ruch nie mógł
        // zapełnić pamięci podręcznej kluczami ani zablokować legalnych żądań.
        var replayKey = string.Concat(token.Kid, ":", token.Timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture), ":", token.Signature);
        if (replayCache.TryGetValue(replayKey, out _))
            return HmacVerificationResult.Fail(HmacVerificationFailure.Replay, token.Kid, tenant);

        replayCache.Set(replayKey, true, TimeSpan.FromTicks(timestampTolerance.Ticks * 2));
        return HmacVerificationResult.Success(token.Kid, tenant);
    }
}
