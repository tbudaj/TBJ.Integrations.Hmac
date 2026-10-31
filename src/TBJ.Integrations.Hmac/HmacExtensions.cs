using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using TBJ.Integrations.Hmac.Internal;

namespace TBJ.Integrations.Hmac;

/// <summary>
/// Rozszerzenia DI rejestrujące schemat uwierzytelniania <c>TBJ-INT-HMAC</c> po stronie serwera
/// oraz podpisujący handler <see cref="HmacSigningHandler"/> po stronie klienta.
/// </summary>
/// <remarks>
/// Obie strony walidują konfigurację zachłannie przy rejestracji (komunikaty po polsku
/// wskazujące klucz), a walidatory <see cref="IValidateOptions{TOptions}"/> pilnują jej
/// także przy późniejszej materializacji opcji.
/// </remarks>
public static class HmacExtensions
{
    /// <summary>
    /// Rejestruje schemat uwierzytelniania <c>TBJ-INT-HMAC</c> pod wskazaną nazwą.
    /// </summary>
    /// <param name="builder">Builder uwierzytelniania z <c>AddAuthentication()</c>.</param>
    /// <param name="authenticationScheme">Nazwa schematu używana w <c>[Authorize]</c> i politykach.</param>
    /// <param name="configureOptions">Konfiguracja opcji serwera (lista klientów, tolerancja czasu, nazwy nagłówków i claimów).</param>
    /// <exception cref="OptionsValidationException">Gdy konfiguracja jest niepoprawna (np. placeholder lub zbyt krótki sekret).</exception>
    public static AuthenticationBuilder AddHmacAuthentication(
        this AuthenticationBuilder builder, string authenticationScheme, Action<HmacServerOptions> configureOptions)
    {
        // Walidacja zachłanna — niepoprawna konfiguracja blokuje start aplikacji już tutaj,
        // zamiast wyjść przy pierwszym żądaniu.
        var probe = new HmacServerOptions();
        configureOptions(probe);
        HmacOptionsValidation.ThrowIfInvalid<HmacServerOptions>(authenticationScheme, HmacOptionsValidation.GetFailures(probe));

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<HmacServerOptions>, HmacServerOptionsValidator>());
        builder.Services.AddMemoryCache();
        builder.Services.TryAddSingleton(TimeProvider.System);

        return builder.AddScheme<HmacServerOptions, HmacAuthenticationHandler>(authenticationScheme, configureOptions);
    }

    /// <summary>
    /// Rejestruje schemat uwierzytelniania <c>TBJ-INT-HMAC</c>, wiążąc opcje z sekcją konfiguracji.
    /// </summary>
    /// <param name="builder">Builder uwierzytelniania z <c>AddAuthentication()</c>.</param>
    /// <param name="authenticationScheme">Nazwa schematu używana w <c>[Authorize]</c> i politykach.</param>
    /// <param name="configurationSection">Sekcja konfiguracji o kształcie <see cref="HmacServerOptions"/>.</param>
    /// <exception cref="OptionsValidationException">Gdy konfiguracja jest niepoprawna (np. placeholder lub zbyt krótki sekret).</exception>
    public static AuthenticationBuilder AddHmacAuthentication(
        this AuthenticationBuilder builder, string authenticationScheme, IConfiguration configurationSection)
        => builder.AddHmacAuthentication(authenticationScheme, options => configurationSection.Bind(options));

    /// <summary>
    /// Dołącza <see cref="HmacSigningHandler"/> do budowanego <c>HttpClient</c> — każde żądanie
    /// zostanie podpisane schematem <c>TBJ-INT-HMAC</c>.
    /// </summary>
    /// <param name="builder">Builder klienta HTTP z <c>AddHttpClient()</c>.</param>
    /// <param name="configureOptions">Konfiguracja opcji podpisywania (kid, sekret, nazwy nagłówków, dostawca korelacji).</param>
    /// <exception cref="OptionsValidationException">Gdy konfiguracja jest niepoprawna (np. placeholder lub zbyt krótki sekret).</exception>
    public static IHttpClientBuilder AddHmacSigning(
        this IHttpClientBuilder builder, Action<HmacSigningOptions> configureOptions)
    {
        // Walidacja zachłanna — niepoprawna konfiguracja blokuje start aplikacji.
        var probe = new HmacSigningOptions();
        configureOptions(probe);
        HmacOptionsValidation.ThrowIfInvalid<HmacSigningOptions>(nameof(HmacSigningOptions), HmacOptionsValidation.GetFailures(probe));

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<HmacSigningOptions>, HmacSigningOptionsValidator>());
        builder.Services.AddOptions<HmacSigningOptions>().Configure(configureOptions);
        builder.Services.AddMemoryCache();
        builder.Services.TryAddSingleton(TimeProvider.System);

        return builder.AddHttpMessageHandler(sp =>
            new HmacSigningHandler(sp.GetRequiredService<IOptions<HmacSigningOptions>>().Value, sp.GetRequiredService<TimeProvider>()));
    }

    /// <summary>
    /// Dołącza <see cref="HmacSigningHandler"/> do budowanego <c>HttpClient</c>, wiążąc opcje
    /// z sekcją konfiguracji.
    /// </summary>
    /// <param name="builder">Builder klienta HTTP z <c>AddHttpClient()</c>.</param>
    /// <param name="configurationSection">Sekcja konfiguracji o kształcie <see cref="HmacSigningOptions"/>.</param>
    /// <exception cref="OptionsValidationException">Gdy konfiguracja jest niepoprawna (np. placeholder lub zbyt krótki sekret).</exception>
    public static IHttpClientBuilder AddHmacSigning(
        this IHttpClientBuilder builder, IConfiguration configurationSection)
        => builder.AddHmacSigning(options => configurationSection.Bind(options));
}
