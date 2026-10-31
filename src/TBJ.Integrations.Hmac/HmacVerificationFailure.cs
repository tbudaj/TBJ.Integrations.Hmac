namespace TBJ.Integrations.Hmac;

/// <summary>Przyczyna odrzucenia weryfikacji żądania — raportowana w wyniku i logach (nigdy wraz z sekretem ani treścią).</summary>
public enum HmacVerificationFailure
{
    /// <summary>Weryfikacja zakończona sukcesem.</summary>
    None,

    /// <summary>Brak nagłówka <c>Authorization</c>.</summary>
    MissingHeader,

    /// <summary>Nagłówek nie da się sparsować (błędny schemat lub brak wymaganych atrybutów).</summary>
    MalformedHeader,

    /// <summary>Wersja protokołu z atrybutu <c>v</c> nie jest obsługiwana.</summary>
    UnsupportedVersion,

    /// <summary>Nieznany identyfikator klucza (<c>kid</c>).</summary>
    UnknownKid,

    /// <summary>
    /// Znacznik czasu poza oknem tolerancji — najczęstsza przyczyna to rozjazd zegarów,
    /// opóźnienie sieciowe lub kolejkowanie po stronie klienta, NIE błędny sekret.
    /// </summary>
    TimestampOutOfRange,

    /// <summary>Hash treści (<c>bh</c>) nie zgadza się z rzeczywistą treścią żądania.</summary>
    BodyHashMismatch,

    /// <summary>Podpis nie zgadza się z żadnym sekretem przypisanym do <c>kid</c>.</summary>
    InvalidSignature,

    /// <summary>To samo żądanie (ten sam <c>kid:ts:sig</c>) zostało już przyjęte — ochrona przed powtórzeniem.</summary>
    Replay,

    /// <summary>Brak identyfikatora tenanta (nagłówek tenanta nieobecny lub pusty).</summary>
    MissingTenant,

    /// <summary>Tenant nie znajduje się na liście dozwolonych dla danego klienta.</summary>
    TenantNotAllowed,
}
