using Microsoft.Extensions.Options;

namespace TBJ.Integrations.Hmac.Internal;

/// <summary>
/// Wspólna walidacja opcji HMAC — uruchamiana zachłannie przy rejestracji w DI oraz
/// przez <see cref="IValidateOptions{TOptions}"/> przy materializacji opcji.
/// </summary>
internal static class HmacOptionsValidation
{
    private const string Placeholder = "<UZUPELNIC>";
    private const int MinSecretLength = 32;

    /// <summary>Zbiera błędy konfiguracji opcji klienta podpisującego.</summary>
    internal static IReadOnlyList<string> GetFailures(HmacSigningOptions options)
    {
        var failures = new List<string>();
        AddCredentialFailures(failures, options.Kid, options.Secret, "HmacSigning:Kid", "HmacSigning:Secret");
        return failures;
    }

    /// <summary>Zbiera błędy konfiguracji opcji serwera.</summary>
    internal static IReadOnlyList<string> GetFailures(HmacServerOptions options)
    {
        var failures = new List<string>();

        if (options.Clients.Count == 0)
        {
            failures.Add("Lista klientów HMAC jest pusta — skonfiguruj przynajmniej jeden wpis w sekcji Clients.");
            return failures;
        }

        for (var i = 0; i < options.Clients.Count; i++)
        {
            var client = options.Clients[i];
            AddCredentialFailures(failures, client.Kid, client.Secret, $"Clients[{i}]:Kid", $"Clients[{i}]:Secret");
        }

        return failures;
    }

    /// <summary>Rzuca <see cref="OptionsValidationException"/>, gdy lista błędów jest niepusta.</summary>
    internal static void ThrowIfInvalid<TOptions>(string optionsName, IReadOnlyList<string> failures)
        where TOptions : class
    {
        if (failures.Count > 0)
            throw new OptionsValidationException(optionsName, typeof(TOptions), failures);
    }

    /// <summary>Wspólne reguły dla pary kid/sekret — niepuste, bez placeholdera, sekret min. 32 znaki.</summary>
    private static void AddCredentialFailures(List<string> failures, string? kid, string? secret, string kidKey, string secretKey)
    {
        if (string.IsNullOrWhiteSpace(kid))
            failures.Add($"Klucz {kidKey} nie może być pusty — wskaż identyfikator klucza (kid).");

        if (string.IsNullOrWhiteSpace(secret))
        {
            failures.Add($"Klucz {secretKey} nie może być pusty — wskaż sekret współdzielony.");
            return;
        }

        if (secret.Contains(Placeholder, StringComparison.Ordinal))
        {
            failures.Add($"Klucz {secretKey} zawiera placeholder '{Placeholder}' — uzupełnij sekret w konfiguracji (np. appsettings.Production.json, zmienna środowiskowa albo user-secrets).");
            return;
        }

        if (secret.Length < MinSecretLength)
            failures.Add($"Klucz {secretKey} musi mieć co najmniej {MinSecretLength} znaki (obecnie {secret.Length}) — użyj długiego, losowego sekretu.");
    }
}
