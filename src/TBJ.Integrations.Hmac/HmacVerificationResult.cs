namespace TBJ.Integrations.Hmac;

/// <summary>Wynik weryfikacji żądania przez <see cref="HmacRequestVerifier"/>.</summary>
/// <param name="Succeeded">Czy żądanie przeszło wszystkie kontrole.</param>
/// <param name="Failure">Przyczyna odrzucenia; <see cref="HmacVerificationFailure.None"/> przy sukcesie.</param>
/// <param name="Kid">Identyfikator klucza z nagłówka — <c>null</c>, gdy nagłówek nie dał się sparsować.</param>
/// <param name="Tenant">Tenant przekazany do weryfikacji.</param>
public sealed record HmacVerificationResult(
    bool Succeeded, HmacVerificationFailure Failure, string? Kid, string? Tenant)
{
    /// <summary>Tworzy wynik pomyślny.</summary>
    internal static HmacVerificationResult Success(string kid, string? tenant)
        => new(true, HmacVerificationFailure.None, kid, tenant);

    /// <summary>Tworzy wynik odrzucenia z podaną przyczyną.</summary>
    internal static HmacVerificationResult Fail(HmacVerificationFailure failure, string? kid, string? tenant)
        => new(false, failure, kid, tenant);
}
