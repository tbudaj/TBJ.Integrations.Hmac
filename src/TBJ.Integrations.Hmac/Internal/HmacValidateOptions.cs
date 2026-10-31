using Microsoft.Extensions.Options;

namespace TBJ.Integrations.Hmac.Internal;

/// <summary>Walidator <see cref="IValidateOptions{TOptions}"/> opcji klienta podpisującego.</summary>
internal sealed class HmacSigningOptionsValidator : IValidateOptions<HmacSigningOptions>
{
    /// <summary>Sprawdza opcje i raportuje wszystkie błędy konfiguracji naraz.</summary>
    public ValidateOptionsResult Validate(string? name, HmacSigningOptions options)
    {
        var failures = HmacOptionsValidation.GetFailures(options);
        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}

/// <summary>Walidator <see cref="IValidateOptions{TOptions}"/> opcji serwera.</summary>
internal sealed class HmacServerOptionsValidator : IValidateOptions<HmacServerOptions>
{
    /// <summary>Sprawdza opcje i raportuje wszystkie błędy konfiguracji naraz.</summary>
    public ValidateOptionsResult Validate(string? name, HmacServerOptions options)
    {
        var failures = HmacOptionsValidation.GetFailures(options);
        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
