namespace TBJ.Integrations.Hmac;

/// <summary>
/// Poświadczenia klienta integracyjnego rozpoznawanego przez serwer — para
/// <see cref="Kid"/>/<see cref="Secret"/> wraz z listą dozwolonych tenantów.
/// </summary>
/// <remarks>
/// Kilka wpisów z tym samym <see cref="Kid"/> oznacza rotację sekretu — serwer próbuje
/// wszystkich sekretów przypisanych do danego identyfikatora, więc stary i nowy sekret
/// działają równolegle przez okres przejściowy.
/// </remarks>
public sealed class HmacClientCredentials
{
    /// <summary>Identyfikator klucza — musi odpowiadać atrybutowi <c>kid</c> wysyłanemu przez klienta.</summary>
    public string Kid { get; set; } = string.Empty;

    /// <summary>Sekret współdzielony — nigdy nie opuszcza konfiguracji serwera.</summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// Lista dozwolonych tenantów (wartości nagłówka tenanta). Pusta lista oznacza
    /// odmowę dla każdego tenanta — klient bez jawnie dozwolonych tenantów nie ma dostępu.
    /// </summary>
    public IList<string> AllowedTenants { get; set; } = new List<string>();
}
