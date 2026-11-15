# Architecture & Socle Commun — pilmil-core

`pilmil-core` est la bibliothèque partagée Kotlin Multiplatform (KMP) des applications Pilmil Studio, intégrée par build composite (`includeBuild("pilmil-core")`) dans chaque projet.

---

## 1. Modules

- **`:core-designsystem`** :
  - Tokens graphiques partagés (`PilmilTokens`, `PilmilColorValues`) et composants Compose Multiplatform réutilisables (`PilmilSwipeableCard`, etc.).
- **`:core-platform`** :
  - Contrat multiplateforme `BackupVault` et implémentation Android `AndroidBackupVault`.
  - Contrat `HapticFeedback` pour les retours haptiques unifiés.

---

## 2. Format de sauvegarde chiffrée `.pilmil` (v1)

Implémenté dans `AndroidBackupVault.kt` (`core-platform`) :
1. **En-tête** : signature `PILMIL` (6 octets ASCII) + octet de version `0x01`.
2. **Compression** : charge utile compressée en **GZIP** avant chiffrement (avec plafond anti-bombe de décompression à **50 Mo** à l'ouverture).
3. **Dérivation de clé** : sel aléatoire de 16 octets (`SecureRandom`), **PBKDF2WithHmacSHA256** à **600 000 itérations** (compatibilité ascendante avec les conteneurs v1 à 100 000 itérations) produisant une clé AES de **256 bits**.
4. **Chiffrement authentifié** : **AES-256-GCM** (`AES/GCM/NoPadding`), IV aléatoire de 12 octets, tag d'authentification de 128 bits, avec l'en-tête (`PILMIL` + version) lié dans les données associées authentifiées (AAD).

---

## 3. Permissions apportées

- Le module `:core-platform` déclare `android.permission.VIBRATE` pour le retour haptique, fusionnée dans les applications qui en dépendent.
- Aucune permission réseau n'est déclarée dans `pilmil-core`.
