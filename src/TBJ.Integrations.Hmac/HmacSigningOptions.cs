namespace TBJ.Integrations.Hmac;

/// <summary>Opcje podpisującego handlera <see cref="HmacSigningHandler"/> po stronie klienta.</summary>
public sealed class HmacSigningOptions
{
    /// <summary>Identyfikator klucza wysyłany jako atrybut <c>kid</c> — musi być znany serwerowi.</summary>
    public string Kid { get; set; } = string.Empty;

    /// <summary>Sekret współdzielony — nigdy nie opuszcza procesu klienta.</summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// Nazwa nagłówka tenanta — wartość ustawia wywołujący na żądaniu, handler włącza ją
    /// do podpisu. Musi odpowiadać <see cref="HmacServerOptions.TenantHeaderName"/> po stronie serwera.
    /// </summary>
    public string TenantHeaderName { get; set; } = "X-Sid";

    /// <summary>
    /// Nazwa nagłówka korelacji — NIE wchodzi do podpisu. Dodawany tylko gdy żądanie go nie ma,
    /// a <see cref="CorrelationIdProvider"/> zwróci wartość.
    /// </summary>
    public string CorrelationHeaderName { get; set; } = "X-Correlation-Id";

    /// <summary>Dostawca identyfikatora korelacji — wywoływany per żądanie.</summary>
    public Func<string?>? CorrelationIdProvider { get; set; }
}
