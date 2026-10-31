# TBJ.Integrations.Hmac

[![build](https://github.com/tbudaj/TBJ.Integrations.Hmac/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/tbudaj/TBJ.Integrations.Hmac/actions/workflows/build-and-test.yml)
[![NuGet](https://img.shields.io/nuget/v/TBJ.Integrations.Hmac)](https://www.nuget.org/packages/TBJ.Integrations.Hmac)

Biblioteka .NET 8/9/10 do **podpisu i weryfikacji żądań HTTP między serwisami** — współdzielony
sekret + HMAC-SHA256, schemat `TBJ-INT-HMAC` v1. Zawiera obie strony protokołu:

- `HmacSigningHandler` — `DelegatingHandler` podpisujący wychodzące żądania `HttpClient`,
- `HmacAuthenticationHandler` — schemat uwierzytelniania ASP.NET Core weryfikujący podpisy,
- `HmacRequestVerifier` — czysty weryfikator niezależny od ASP.NET Core (do użycia poza pipeline'em HTTP).

Sekret nigdy nie opuszcza procesu — w sieci przesyłany jest wyłącznie podpis ważny przez
krótkie okno czasu i związany z metodą, ścieżką, treścią żądania oraz tenantem.

---

## Spis treści

- [Protokół TBJ-INT-HMAC v1](#protokół-tbj-int-hmac-v1)
- [Instalacja](#instalacja)
- [Konfiguracja serwera](#konfiguracja-serwera)
- [Konfiguracja klienta](#konfiguracja-klienta)
- [Kody odrzuceń i kody HTTP](#kody-odrzuceń-i-kody-http)
- [Rotacja sekretów](#rotacja-sekretów)
- [Bezpieczeństwo](#bezpieczeństwo)

---

## Protokół TBJ-INT-HMAC v1

### Nagłówek

```
Authorization: TBJ-INT-HMAC v=1;ts=<unix sekundy UTC>;kid=<kid>;bh=<base64url(SHA-256(treść))>;sig=<base64url(HMAC-SHA256)>
```

- Base64Url **bez paddingu**: `+` → `-`, `/` → `_`, bez końcowych `=`.
- Parser jest tolerancyjny na nieznane atrybuty; wymaga `v`, `ts`, `kid`, `bh`, `sig`.
- `bh` liczony jest **zawsze**, także dla pustej treści (SHA-256 pustego ciągu).

### Ciąg kanoniczny

UTF-8, wiersze rozdzielone `\n`:

```
v1
<ts>
<METODA wielkimi literami>
<ścieżka z query w formie drutowej>
<bh>
<tenant lub pusty>
```

Ścieżka drutowa — klient podpisuje `request.RequestUri.PathAndQuery`, serwer odtwarza
`PathBase.ToUriComponent() + Path.ToUriComponent() + QueryString.ToUriComponent()`
(czyli dokładnie formę percent-encoded, która trafiła na drut).

### Nagłówki pomocnicze (poza podpisem)

- `X-Sid` — identyfikator tenanta (nazwa konfigurowalna `TenantHeaderName`); wartość wchodzi
  do podpisu jako ostatni wiersz ciągu kanonicznego.
- `X-Correlation-Id` — korelacja (nazwa konfigurowalna `CorrelationHeaderName`); **nie**
  wchodzi do podpisu.

---

## Instalacja

W repozytoriach z Central Package Management (`Directory.Packages.props`):

```xml
<!-- Directory.Packages.props -->
<PackageVersion Include="TBJ.Integrations.Hmac" Version="1.0.0" />
```

```xml
<!-- plik .csproj konsumenta -->
<PackageReference Include="TBJ.Integrations.Hmac" />
```

---

## Konfiguracja serwera

```csharp
builder.Services.AddAuthentication()
    .AddHmacAuthentication("integracja", options =>
    {
        options.Clients.Add(new HmacClientCredentials
        {
            Kid = "svc-orders",
            Secret = builder.Configuration["Integracja:Secret"]!,
            AllowedTenants = { "S-100", "S-200" },
        });
    });
builder.Services.AddAuthorization();
```

albo z sekcją konfiguracji:

```csharp
builder.Services.AddAuthentication()
    .AddHmacAuthentication("integracja", builder.Configuration.GetSection("Hmac"));
```

```json
{
  "Hmac": {
    "TimestampToleranceSeconds": 300,
    "TenantHeaderName": "X-Sid",
    "Clients": [
      { "Kid": "svc-orders", "Secret": "<sekret min. 32 znaki>", "AllowedTenants": [ "S-100" ] }
    ]
  }
}
```

Endpoint/ kontroler chroni się standardowo:

```csharp
endpoints.MapGet("/api/zlecenia", ...)
    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "integracja" });
```

Po uwierzytelnieniu `ClaimsPrincipal` zawiera:

- claim tenanta (typ `Sid`, konfigurowalny `TenantClaimType`),
- claim klienta = `kid` (typ `IntegrationClient`, konfigurowalny `ClientClaimType`).

Niepoprawna konfiguracja (pusty kid, placeholder `<UZUPELNIC>`, sekret krótszy niż 32 znaki,
pusta lista klientów) **blokuje start aplikacji** wyjątkiem `OptionsValidationException`
z komunikatem po polsku wskazującym klucz.

---

## Konfiguracja klienta

```csharp
services.AddHttpClient("orders-api", c => c.BaseAddress = new Uri("https://api/"))
    .AddHmacSigning(options =>
    {
        options.Kid = "svc-orders";
        options.Secret = "<sekret współdzielony>";
        options.CorrelationIdProvider = () => Activity.Current?.Id;
    });
```

Wywołujący ustawia nagłówek tenanta na żądaniu (wartość wchodzi do podpisu):

```csharp
var request = new HttpRequestMessage(HttpMethod.Get, "/api/zlecenia");
request.Headers.Add("X-Sid", "S-100");
var response = await client.SendAsync(request);
```

Handler sam: buforuje treść, liczy `bh`, dokłada `X-Correlation-Id` (tylko gdy żądanie go nie ma),
odczytuje tenanta z nagłówka i ustawia `Authorization`. Każde wysłanie dostaje świeży znacznik
czasu, więc ponowienia z polityk retry są poprawnie podpisane.

---

## Kody odrzuceń i kody HTTP

`HmacRequestVerifier` zwraca `HmacVerificationResult` z przyczyną (`HmacVerificationFailure`);
handler mapuje ją na odpowiedź HTTP i zapisuje ostrzeżenie w logu (bez sekretów i bez treści):

| Przyczyna | Kiedy | HTTP |
|---|---|---|
| `MissingHeader` / `MalformedHeader` | brak lub uszkodzony nagłówek | 401 |
| `UnsupportedVersion` | `v` ≠ 1 | 401 |
| `UnknownKid` | `kid` nieznany serwerowi | 401 |
| `TimestampOutOfRange` | `ts` poza oknem (domyślnie ±300 s) — sprawdź zegary, nie sekret | 401 |
| `BodyHashMismatch` | `bh` ≠ hash rzeczywistej treści | 401 |
| `InvalidSignature` | podpis nie pasuje do żadnego sekretu dla `kid` | 401 |
| `MissingTenant` | brak nagłówka tenanta | 401 |
| `TenantNotAllowed` | tenant spoza `AllowedTenants` (lub lista pusta) | **403** |
| `Replay` | to samo `kid:ts:sig` już przyjęte | 401 |

Odpowiedzi 401 zawierają `WWW-Authenticate: TBJ-INT-HMAC`.

---

## Rotacja sekretów

Kilka wpisów z tym samym `Kid` oznacza rotację — serwer próbuje wszystkich sekretów:

```csharp
options.Clients.Add(new HmacClientCredentials { Kid = "svc-orders", Secret = "<nowy>", AllowedTenants = { "S-100" } });
options.Clients.Add(new HmacClientCredentials { Kid = "svc-orders", Secret = "<stary>", AllowedTenants = { "S-100" } });
```

Procedura:

1. Dodaj nowy sekret jako kolejny wpis z tym samym `Kid` (stary zostaje).
2. Wdróż serwer — oba sekrety działają równolegle.
3. Przełącz klienta na nowy sekret.
4. Po okresie przejściowym usuń stary wpis i wdróż ponownie.

---

## Bezpieczeństwo

- Sekret min. 32 znaki, losowy; placeholder `<UZUPELNIC>` blokuje start.
- Porównanie podpisów i hashy jest stałoczasowe (`CryptographicOperations.FixedTimeEquals`).
- Ochrona przed powtórzeniem: `kid:ts:sig` trzymane w `IMemoryCache` przez 2× tolerancję czasu;
  sprawdzane **po** poprawnym podpisie.
- Treść żądania buforowana po stronie serwera z limitem `MaxBodyBytes` (domyślnie 100 MB).
- Protokół wymaga HTTPS na produkcji — podpis chroni integralność i autentyczność,
  ale nie zastępuje szyfrowania transportu.
