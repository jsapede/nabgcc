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

## Dépendances

- `arm-none-eabi-gcc` (compilateur croisé ARM)
- `arm-none-eabi-binutils`
- PHP (pour la génération du fichier .sim)
- OpenOCD (pour le flash via JTAG, optionnel)

## Compilation

```bash
make          # compile → bin/Nab.elf → bin/Nab.bin
php -f sim.php # (optionnel) génère wpa2.sim
```

Le fichier `.sim` peut être uploadé sur le lapin via :
1. **HTTP** : bouton maintenu au démarrage → page web → upload .sim
2. **JTAG** : `openocd -f openocd/nabaztagv2.cfg`

## Structure du projet

```
src/net/          — WiFi, EAPOL, AES, hash, RC4
src/usb/          — Driver RT2501 USB
src/hal/          — Drivers matériels (UART, I2C, SPI, LED, audio, moteur)
src/vm/           — Machine virtuelle MTL (bytecode interpreter)
mtl/              — Sources MTL du bytecode embarqué (page web boot)
inc/              — Headers
sys/              — Startup ARM, linker script
testvm/           — VM de test
openocd/          — Configuration JTAG
```

## Licence

MIT — voir [LICENSE](LICENSE). Basé sur le travail de :
- [andreax79/ServerlessNabaztag](https://github.com/andreax79/ServerlessNabaztag)
- [RedoXyde/nabgcc](https://github.com/RedoXyde/nabgcc)
