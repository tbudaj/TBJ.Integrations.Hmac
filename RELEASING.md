# Wydawanie paczek i rozwój

Ten dokument opisuje zasady publikacji paczki NuGet oraz rozwój tego repozytorium.

## Wersjonowanie

Projekt używa [MinVer](https://github.com/adamralph/minver). Wersja jest automatycznie odczytywana z tagu Git.

**Prefiks tagu dla tego repozytorium:** `hmac/v` (np. `hmac/v1.2.3`)

## Publikacja paczki

Aby opublikować nową wersję:

1. Upewnij się, że gałąź `main` jest stabilna i testy przechodzą.
2. Utwórz i wypchnij tag:

   ```bash
   git checkout main
   git pull origin main
   git tag hmac/v1.2.3
   git push origin hmac/v1.2.3
   ```

3. Workflow `release.yml` automatycznie:
   - zbuduje projekt,
   - opublikuje paczkę `TBJ.Integrations.Hmac` na NuGet.org (Trusted Publishing) i GitHub Packages,
   - utworzy GitHub Release,
   - zamrozi kod w gałęzi `release/hmac/1.2.3`.

## Gałęzie

- `main` — aktywny rozwój. Wszystkie zmiany trafiają przez PR.
- `release/<prefiks>/<wersja>` — zamrożone wydanie. Służy do hotfixów.

## Hotfix

1. Utwórz gałąź z właściwej gałęzi release:

   ```bash
   git checkout -b hotfix/hmac-1.2.3 release/hmac/1.2.3
   ```

   Możesz też utworzyć ją z `main`, jeśli poprawka jest już tam wprowadzona.
2. Wprowadź poprawki.
3. Otwórz PR do gałęzi `release/hmac/1.2.3`.
4. Po zatwierdzeniu i merge wypchnij nowy tag:

   ```bash
   git tag hmac/v1.2.4
   git push origin hmac/v1.2.4
   ```

## Wymagane PR i ochrona gałęzi

Gałęzie `main` i `release/*` są chronione rulesetami:

- wymagany jest przynajmniej jeden review (CODEOWNERS),
- wymagany jest status check `build`,
- bezpośrednie push są zablokowane (admin może bypassować w wyjątkowych sytuacjach).

## Sekrety w repozytorium

Wymagane sekrety w ustawieniach repozytorium (Settings → Secrets and variables → Actions):

- `NUGET_USER` — nazwa użytkownika na NuGet.org.
- `RELEASE_PAT` — GitHub PAT z zakresami `repo` i `workflow`, używany do tworzenia gałęzi release.

## Trusted Publishing

Publikacja na NuGet.org odbywa się przez Trusted Publishing (OIDC). Na NuGet.org dla paczki `TBJ.Integrations.Hmac` musi być skonfigurowana polityka zaufania dla repozytorium `tbudaj/TBJ.Integrations.Hmac` i workflow `release.yml`.
