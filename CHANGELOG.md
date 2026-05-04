# Changelog — nabgcc WPA2

## [WPA2] — 2026-05-04

### Ajouté
- Support WPA2 complet (AES-CCMP, IEEE 802.11i)
- AES-128, AES-CTR, CCMP-MIC (`src/net/aes.c`)
- SHA256, HMAC-SHA256, PBKDF2-SHA256 (`src/net/hash.c`)
- Détection RSN IE au scan WiFi → `CRYPT_WPA2`
- Case `CRYPT_WPA2` dans `rt2501_auth()` avec PBKDF2 pour dérivation PMK
- Case `CRYPT_WPA2` dans `ieee80211_associate()` — construction RSN IE
- CCMP overhead et TX descriptor dans `rt2501_send()`
- Installation de clé AES (`RT2501_CIPHER_AES`) dans `eapol.c`
- `case RT2501_CIPHER_AES: key_length = 16` dans `rt2501_set_key()` (correction : la clé n'était jamais écrite)
- Option WPA2 dans le formulaire HTML de la page web boot

### Modifié
- `inc/net/ieee80211.h` — ajout `IEEE80211_CRYPT_WPA2 = 5`
- `inc/net/hash.h` — déclarations `hmac_sha256()`, `pbkdf2_sha256()`
- `inc/net/eapol.h` — constantes inchangées
- `mtl/boot.*.mtl` — formulaire de configuration WiFi avec WPA2

### Supprimé
- `IEEE80211_CRYPT_WPA2_MIXED` (inutile — WPA2 pur AES-CCMP)

### Corrigé (bugs originaux)
- `rt2501_set_key()` : `RT2501_CIPHER_AES` n'avait pas de `key_length` défini (0), la clé AES n'était jamais écrite dans le chipset WiFi
