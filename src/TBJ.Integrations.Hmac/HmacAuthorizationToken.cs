namespace TBJ.Integrations.Hmac;

/// <summary>Sparsowana zawartość nagłówka <c>Authorization: TBJ-INT-HMAC ...</c>.</summary>
/// <param name="Version">Wersja protokołu z atrybutu <c>v</c>.</param>
/// <param name="Timestamp">Znacznik czasu Unix (sekundy, UTC) z atrybutu <c>ts</c>.</param>
/// <param name="Kid">Identyfikator klucza z atrybutu <c>kid</c>.</param>
/// <param name="BodyHash">Hash treści żądania (Base64Url) z atrybutu <c>bh</c>.</param>
/// <param name="Signature">Podpis HMAC-SHA256 (Base64Url) z atrybutu <c>sig</c>.</param>
public readonly record struct HmacAuthorizationToken(
    int Version, long Timestamp, string Kid, string BodyHash, string Signature);
