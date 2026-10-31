using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TBJ.Integrations.Hmac;

/// <summary>
/// Algorytm podpisu HMAC-SHA256 protokołu <c>TBJ-INT-HMAC</c> (v1) — współdzielony przez stronę
/// podpisującą (<see cref="HmacSigningHandler"/>) i weryfikującą (<see cref="HmacRequestVerifier"/>),
/// co eliminuje ryzyko rozjazdu dwóch niezależnych implementacji tego samego algorytmu.
/// </summary>
/// <remarks>
/// <para>
/// Format nagłówka:
/// <c>Authorization: TBJ-INT-HMAC v=1;ts=&lt;unix UTC&gt;;kid=&lt;kid&gt;;bh=&lt;base64url(SHA-256(treść))&gt;;sig=&lt;base64url(HMAC-SHA256)&gt;</c>.
/// </para>
/// <para>
/// Ciąg kanoniczny (UTF-8, separator <c>\n</c>):
/// <c>v1\n{ts}\n{METODA wielkimi}\n{ścieżka z query}\n{bh}\n{tenant lub pusty}</c>.
/// </para>
/// <para>
/// Sekret nigdy nie opuszcza procesu — w sieci przesyłany jest wyłącznie podpis ważny przez krótkie
/// okno czasu i związany z metodą, ścieżką, treścią żądania oraz tenantem.
/// </para>
/// </remarks>
public static class HmacSignature
{
    /// <summary>Nazwa schematu uwierzytelnienia używana w nagłówku <c>Authorization</c>.</summary>
    public const string SchemeName = "TBJ-INT-HMAC";

    /// <summary>Wersja protokołu obsługiwana przez tę bibliotekę.</summary>
    public const int ProtocolVersion = 1;

    /// <summary>
    /// Buduje ciąg kanoniczny podpisywania: <c>v1\n{ts}\n{METODA}\n{ścieżka z query}\n{bh}\n{tenant}</c>.
    /// </summary>
    /// <param name="timestampUnixSeconds">Znacznik czasu UTC w sekundach (Unix time).</param>
    /// <param name="method">Metoda HTTP — normalizowana do wielkich liter.</param>
    /// <param name="pathAndQuery">Ścieżka wraz z query w formie drutowej (percent-encoded).</param>
    /// <param name="bodyHash">Hash treści <c>base64url(SHA-256(treść))</c> — patrz <see cref="ComputeBodyHash"/>.</param>
    /// <param name="tenant">Identyfikator tenanta; <c>null</c> traktowany jako pusty łańcuch.</param>
    public static string BuildCanonical(long timestampUnixSeconds, string method, string pathAndQuery, string bodyHash, string? tenant)
    {
        return string.Concat(
            "v", ProtocolVersion.ToString(CultureInfo.InvariantCulture), "\n",
            timestampUnixSeconds.ToString(CultureInfo.InvariantCulture), "\n",
            method.ToUpperInvariant(), "\n",
            pathAndQuery, "\n",
            bodyHash, "\n",
            tenant ?? string.Empty);
    }

    /// <summary>
    /// Oblicza hash SHA-256 treści żądania zakodowany jako Base64Url (bez paddingu) — wartość
    /// atrybutu <c>bh</c>. Liczony zawsze, także dla pustej treści (SHA-256 pustego ciągu).
    /// </summary>
    public static string ComputeBodyHash(ReadOnlySpan<byte> body)
        => ToBase64Url(SHA256.HashData(body));

    /// <summary>
    /// Oblicza podpis HMAC-SHA256 ciągu kanonicznego kluczem <paramref name="secret"/>,
    /// zakodowany jako Base64Url (bez paddingu) — wartość atrybutu <c>sig</c>.
    /// </summary>
    /// <param name="secret">Sekret współdzielony — nigdy nie trafia na drut.</param>
    /// <param name="canonical">Ciąg kanoniczny z <see cref="BuildCanonical"/>.</param>
    public static string ComputeSignature(string secret, string canonical)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var messageBytes = Encoding.UTF8.GetBytes(canonical);
        var hash = HMACSHA256.HashData(keyBytes, messageBytes);
        return ToBase64Url(hash);
    }

    /// <summary>
    /// Buduje kompletną wartość nagłówka <c>Authorization</c> dla podanego żądania —
    /// łącznie z nazwą schematu <see cref="SchemeName"/>.
    /// </summary>
    /// <param name="kid">Identyfikator klucza (key id) — podpowiedź dla serwera przy wyborze sekretu.</param>
    /// <param name="secret">Sekret współdzielony.</param>
    /// <param name="timestampUnixSeconds">Znacznik czasu UTC w sekundach (Unix time).</param>
    /// <param name="method">Metoda HTTP.</param>
    /// <param name="pathAndQuery">Ścieżka wraz z query w formie drutowej (percent-encoded).</param>
    /// <param name="body">Surowa treść żądania (może być pusta — <c>bh</c> liczony jest zawsze).</param>
    /// <param name="tenant">Identyfikator tenanta wchodzący do podpisu; <c>null</c> = pusty.</param>
    public static string BuildAuthorizationHeader(
        string kid, string secret, long timestampUnixSeconds,
        string method, string pathAndQuery, ReadOnlySpan<byte> body, string? tenant)
    {
        var bodyHash = ComputeBodyHash(body);
        var canonical = BuildCanonical(timestampUnixSeconds, method, pathAndQuery, bodyHash, tenant);
        var signature = ComputeSignature(secret, canonical);

        var sb = new StringBuilder();
        sb.Append(SchemeName).Append(' ');
        sb.Append("v=").Append(ProtocolVersion).Append(';');
        sb.Append("ts=").Append(timestampUnixSeconds).Append(';');
        sb.Append("kid=").Append(kid).Append(';');
        sb.Append("bh=").Append(bodyHash).Append(';');
        sb.Append("sig=").Append(signature);
        return sb.ToString();
    }

    /// <summary>
    /// Parsuje wartość nagłówka <c>Authorization</c> schematu <see cref="SchemeName"/>.
    /// Tolerancyjny na nieznane atrybuty; wymaga obecności <c>v</c>, <c>ts</c>, <c>kid</c>,
    /// <c>bh</c> i <c>sig</c>.
    /// </summary>
    /// <returns><c>true</c>, gdy nagłówek ma właściwy schemat i komplet wymaganych atrybutów.</returns>
    public static bool TryParse(string? headerValue, out HmacAuthorizationToken token)
    {
        token = default;
        if (string.IsNullOrWhiteSpace(headerValue))
            return false;

        var spaceIndex = headerValue.IndexOf(' ');
        if (spaceIndex < 0)
            return false;

        var scheme = headerValue[..spaceIndex];
        if (!string.Equals(scheme, SchemeName, StringComparison.Ordinal))
            return false;

        var attributesPart = headerValue[(spaceIndex + 1)..];
        int? version = null;
        long? timestamp = null;
        string? kid = null;
        string? bodyHash = null;
        string? signature = null;

        // Tolerancja na nieznane atrybuty — przyszłe wersje protokołu mogą dopisać własne pola,
        // a starsza strona po prostu je zignoruje.
        foreach (var rawAttribute in attributesPart.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIndex = rawAttribute.IndexOf('=');
            if (eqIndex < 0) continue;

            var name = rawAttribute[..eqIndex];
            var value = rawAttribute[(eqIndex + 1)..];

            switch (name)
            {
                case "v": version = int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var v) ? v : null; break;
                case "ts": timestamp = long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ts) ? ts : null; break;
                case "kid": kid = value; break;
                case "bh": bodyHash = value; break;
                case "sig": signature = value; break;
            }
        }

        if (version is null || timestamp is null
            || string.IsNullOrEmpty(kid) || string.IsNullOrEmpty(bodyHash) || string.IsNullOrEmpty(signature))
            return false;

        token = new HmacAuthorizationToken(version.Value, timestamp.Value, kid, bodyHash, signature);
        return true;
    }

    /// <summary>
    /// Porównuje dwa podpisy (lub hashe) Base64Url w czasie stałym.
    /// Zwraca <c>false</c> dla wejścia niebędącego poprawnym Base64Url.
    /// </summary>
    internal static bool FixedTimeEqualsBase64Url(string expected, string actual)
    {
        var expectedBytes = TryDecodeBase64Url(expected);
        var actualBytes = TryDecodeBase64Url(actual);

        return expectedBytes is not null && actualBytes is not null
            && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }

    /// <summary>Koduje bajty jako Base64Url bez paddingu (<c>+</c>→<c>-</c>, <c>/</c>→<c>_</c>, bez <c>=</c>).</summary>
    private static string ToBase64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Dekoduje ciąg Base64Url na bajty; zwraca <c>null</c> zamiast rzucać dla nieprawidłowego wejścia.</summary>
    private static byte[]? TryDecodeBase64Url(string value)
    {
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "="; break;
            }
            return Convert.FromBase64String(padded);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
