# nabgcc — Nabaztag GCC Firmware avec support WPA2

Fork de [RedoXyde/nabgcc](https://github.com/RedoXyde/nabgcc) avec ajout du support **WPA2 (AES-CCMP)**.

Ce firmware est le **firmware de boot** du Nabaztag (processeur ARM7TDMI). Il gère le WiFi, le réseau IP, le chargement du bytecode MTL (`bc.jsp`) et la page web de configuration accessible en maintenant le bouton appuyé au démarrage.

## Nouveautés WPA2

- **WPA2-PSK (AES-CCMP)** — connexion aux réseaux WiFi protégés en WPA2
- **PBKDF2-SHA256** — dérivation du PMK depuis la passphrase (4096 itérations)
- **AES-128 (ECB/CTR)** + **CCMP-MIC** — crypto embarquée pour le chiffrement des données
- **SHA256, HMAC-SHA256** — fonctions de hachage pour le 4-way handshake
- **Détection RSN IE** — scan et association WPA2
- **Page web boot** — option WPA2 dans le formulaire de configuration WiFi

## Options de connexion WiFi

| Type | Valeur | Chiffrement |
|------|--------|-------------|
| None | 0 | Aucun |
| WEP64 | 1 | RC4 40-bit |
| WEP128 | 2 | RC4 104-bit |
| WPA | 3 | TKIP/RC4 |
| **WPA2** | **5** | **AES-CCMP** |

## Compilation

**Prérequis :** `arm-none-eabi-gcc` (compilateur croisé ARM), `arm-none-eabi-binutils`, Python 3.

```bash
# Étape 1 : Compiler le firmware
make                    # produit bin/Nab.elf + bin/Nab.bin

# Étape 2 : Générer le fichier flashable
python3 sim.py          # produit wpa2.sim (firmware à uploader)

# Ou en une seule commande :
make sim                # compile + génère wpa2.sim
```

Le fichier `wpa2.sim` peut être uploadé sur le lapin via :
1. **HTTP** : bouton maintenu au démarrage → page web → upload `.sim`
2. **JTAG** : `openocd -f openocd/nabaztagv2.cfg`

> ⚠️ Taille max du `.sim` : **256 KB**. Le firmware actuel pèse **~225 KB**.

## Dépendances

- `arm-none-eabi-gcc` + `arm-none-eabi-binutils` — compilateur croisé ARM
- `python3` — génération du `.sim` (ou `php` pour la version historique `sim.php`)
- `openocd` — flash via JTAG (optionnel)

## Structure du projet

```
src/net/          — WiFi (IEEE 802.11), EAPOL, AES, SHA, RC4
src/usb/          — Driver chipset WiFi RT2501 (USB)
src/hal/          — Drivers matériels (UART, I2C, SPI, LED, audio, moteur)
src/vm/           — Machine virtuelle MTL (interpréteur de bytecode)
src/main.c        — Point d'entrée du firmware
src/bc.c          — Bytecode embarqué (page web de configuration boot)
mtl/              — Sources MTL du bytecode boot (10 versions)
inc/              — Headers
sys/              — Startup ARM, linker script
testvm/           — VM de test
openocd/          — Configuration et scripts JTAG
```

## Historique

Ce repo est un fork de [RedoXyde/nabgcc](https://github.com/RedoXyde/nabgcc), lui-même issu du travail de [andreax79/ServerlessNabaztag](https://github.com/andreax79/ServerlessNabaztag). Les modifications WPA2 sont dans la branche `master` (tag `v0.1.0-wpa2`).

## Licence

MIT — voir [LICENSE](LICENSE).
