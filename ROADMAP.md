# Feuille de route — pilmil-core

> Dernière mise à jour : novembre 2026. Décision d'architecture : [docs/IPHONE_ET_MUTUALISATION.md](docs/IPHONE_ET_MUTUALISATION.md).

## 1. Rôle du socle commun
`pilmil-core` reste volontairement un **petit noyau stable** (pas de design system unique imposé aux applis) centré sur :
- `core-platform` : coffre-fort de sauvegarde locale chiffrée `.pilmil` (`BackupVault`, AES-256-GCM + PBKDF2) et retour haptique multiplateforme (`HapticFeedback`).
- `core-designsystem` : tokens de base et composants optionnels (`PilmilSwipeableCard`).

## 2. Fonctionnalités à venir
- Implémenter `IosBackupVault` (`iosMain`, via `CommonCrypto` / `CryptoKit`) pour que le format `.pilmil` soit 100 % interopérable Android ↔ iOS.
- Intégrer `pilmil-core` par sous-module Git (avec `submodules: true` en CI) dans les applications au moment de leur portage KMP/iOS, en commençant par **Sommelle** et **Lunaison** pour la sauvegarde chiffrée.

## 3. Qualité de code & sécurité
- Exécuter `testDebugUnitTest`, `lintDebug` et `assembleDebug` en CI.
- Ajouter des tests d'interopérabilité / vecteurs de test sur `BackupVault` (format `.pilmil` v1, phrases secrètes invalides, conteneurs tronqués) et `ktlint` / `detekt`.

## 4. Feuille de route iOS
- `IosHapticFeedback.kt` est déjà présent dans `core-platform/src/iosMain`.
- Prochaine étape : ajouter la cible `iosSimulatorArm64` / `iosArm64` dans la CI GitHub Actions de `pilmil-core` (runner `macos-15`) dès l'ajout de `IosBackupVault`.
