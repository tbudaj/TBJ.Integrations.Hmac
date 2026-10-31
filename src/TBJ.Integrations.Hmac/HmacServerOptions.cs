using Microsoft.AspNetCore.Authentication;

namespace TBJ.Integrations.Hmac;

/// <summary>Opcje schematu uwierzytelniania <c>TBJ-INT-HMAC</c> po stronie serwera.</summary>
public sealed class HmacServerOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Poświadczenia znanych klientów. Kilka wpisów z tym samym <see cref="HmacClientCredentials.Kid"/>
    /// oznacza rotację sekretu — serwer próbuje wszystkich.
    /// </summary>
    public IList<HmacClientCredentials> Clients { get; set; } = new List<HmacClientCredentials>();

    /// <summary>Dopuszczalne odchylenie znacznika czasu <c>ts</c> od zegara serwera (w sekundach).</summary>
    public int TimestampToleranceSeconds { get; set; } = 300;

    /// <summary>Nazwa nagłówka niosącego identyfikator tenanta.</summary>
    public string TenantHeaderName { get; set; } = "X-Sid";

    /// <summary>Typ claimu, pod którym trafia tenant po pomyślnym uwierzytelnieniu.</summary>
    public string TenantClaimType { get; set; } = "Sid";

    /// <summary>Typ claimu, pod którym trafia identyfikator klienta (<c>kid</c>) po pomyślnym uwierzytelnieniu.</summary>
    public string ClientClaimType { get; set; } = "IntegrationClient";

    /// <summary>
    /// Maksymalny rozmiar buforowanej treści żądania w bajtach — treść musi zostać odczytana,
    /// by zweryfikować <c>bh</c>. Większa treść powoduje odrzucenie żądania.
    /// </summary>
    public long MaxBodyBytes { get; set; } = 100 * 1024 * 1024;
}
