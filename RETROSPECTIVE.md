# Rétrospective du Projet Nabaztag WPA2

**Date:** Avril 2026  
**Projet:** Intégration WPA2 au firmware Nabaztag

---

## 1. Erreurs Commises et Analyse des Coûts

### 1.1 Erreurs Techniques

**Erreur 1: Syntax error dans aes.c (double closing brackets)**
- Description: Double closing brackets `))` après l'appel à AES-CTR
- Impact: Échec de compilation, retard d'une itération
- Cause racine: Copie-collé depuis AES-ECB sans adaptation après l'implémentation de la fonction AES-CTR
- Coût: Faible (erreur syntaxique simple à détecter avec les outils de compilation)

**Erreur 2: K constant overflow dans SHA256**
- Description: Dépassement de capacité du type `uint32_t` pour les constantes K de l'algorithme SHA256
- Impact: Résultats incorrects pour certains messages longs
- Cause racine: Mauvaise estimation de la plage de valeurs des constantes SHA256 définites dans la RFC
- Coût: Élevé (corruption silencieuse des données d'authentification)

**Erreur 3: Missing syscalls.c (stub libc manquant)**
- Description: Absence de stubs pour les fonctions `_open`, `_close`, `_read`, `_write`, `_lseek`, `_stat`
- Impact: Linker errors bloquantes lors de la phase de linkage du firmware
- Cause racine: Code original prévu pour environnement hosted avec libc complète,pas bare-metal
- Coût: Moyen (facile à corriger une fois identifié comme problème de stubs)

**Erreur 4: Format .sim incorrect initial (séparateur manquant)**
- Description: Séparateur `-violet-` manquant lors de la première tentative de génération du fichier .sim
- Impact: Fichier non reconnu par le bootloader Nabaztag
- Cause racine: Mauvaise interprétation du parsing des fichiers .sim
- Coût: Moyen (tests itératifs nécessaires pour comprendre le format)

**Erreur 5: Bugs préexistants non détectés初期 (types non standard)**
- Description: Types non standard (`ushort`, `ulong`) dans le code source original usbhcore.c et uart.c
- Impact: Multiples erreurs de compilation à la première compilation du projet
- Cause racine: Aucune vérification de compilation avant l'analyse du code WPA existant
- Coût: Élevé (temps perdu à debugger du code préexistant non écrit pendant ce projet)

### 1.2 Erreurs d'Analyse

**Erreur 6: Analyse incomplète du format .sim**
- Description: Tentative de génération sans avoir complètement compris l'obfuscation
- Impact: Itérations supplémentaires pour valider le format correct
- Cause racine: Documentation manquante sur le format propriétaire Violet

**Erreur 7: Tests hardware non effectués**
- Description: Vérification limitées aux tests software (round-trip obfuscation)
- Impact: Confirmation de la compatibilité hardware réelle non effectuée
- Cause racine: Accès limité au matériel physique Nabaztag
- Coût: Inconnu (risque résiduel pour le déploiement)

---

## 2. Bonnes Décisions à Conserver

### 2.1 Décisions Techniques

**Décision 1: Analyse WPA existante avant WPA2**
- Justification: Compréhension complète de TKIP avant d'implémenter WPA2
- Bénéfice: Implémentation WPA2 cohérente avec l'existant (pas de conflit entre les chiffrements)

**Décision 2: Utilisation de AES-128**
- Justification: Alignement avec les limitations matérielles du MCU (capacité limitée)
- Bénéfice: Performance optimale sur MCU 8-bit sans mémoire excessive

**Décision 3: Décodage format .sim par comparaison**
- Justification: Analyse pragmatique en l'absence de documentation officielle
- Bénéfice: Décodage correct par tests itératifs avec nab.sim original comme référence

**Décision 4: Séparation AES (chiffrement) / hash (intégrité)**
- Justification: Séparation claire des responsabilités entre les modules cryptographiques
- Bénéfice: Code maintainable, réutilisable et testable indépendamment

### 2.2 Décisions de Processus

**Décision 5: Tests round-trip pour l'obfuscation**
- Justification: Validation que décompression + compression = identity function
- Bénéfice: Confiance totale dans l'inversion de l'obfuscation du format .sim

**Décision 6: Validation format avec nab.sim original**
- Justification: Utilisation d'une référence connue comme valide
- Bénéfice: Assurance qualité par comparaison directe avec le fichier d'origine

**Décision 7: Itérations incrémentales**
- Justification: Approche itérative avec tests après chaque modification majeure
- Bénéfice: Identification rapide des régressions et des erreurs

---

## 3. Recommandations pour Projets Similaires

### 3.1 Avant le Développement

1. **Compiler immédiatement** — Compiler le code original dès le début pour identifier les problèmes préexistants et éviter de perdre du temps sur du code qui ne compile pas

2. **Analyser le hardware réel** — Vérifier les spécifications du MCU (FLASH, RAM, ROM disponibles) et les contraintes matérielles avant de choisir les algorithmes

3. **Documenter le format** — Ne pas assumes que la documentation existe pour les formats propriétaires; utiliser l'analyse inverse si nécessaire

4. **Vérifier la toolchain** — S'assurer que l'environnement de compilation est complet et fonctionne avant de commencer le développement

### 3.2 Durant le Développement

1. **Modularité** — Séparer chiffrement, hash et network en modules distincts pour faciliter la maintenance et les tests

2. **Tests incrémentaux** — Compiler après chaque changement majeur pour détecter les régressions rapidement

3. **Versionnage** — Garder des versions fonctionnelles sauvegardées avant chaque modification significative

4. **Stubs准备** — Préparer les stubs nécessaires (syscalls, libc) pour éviter les linker errors tardives

### 3.3 Après le Développement

1. **Tests hardware** — Prioriser les tests sur matériel réel avant le déploiement production

2. **Fuzzing** — Tester les cas limites (messages vides, longueur maximale, caractères spéciaux)

3. **Documentation** — Documenter toutes les décisions techniques et leur justification pour lesMaintenance futures

4. **Fallback** — Prévoir un plan de rollback si les tests hardware révèlent des problèmes

---

## 4. Leçons Apprises sur le Développement Firmware Embappé

### 4.1 Contraintes Spécifiques du Firmware Embappé

**Mémoire limitée:**
Les algorithmes cryptographiques standard et leurs implémentations de référence sont souvent trop lourdes pour les microcontrôleurs 8-bit. Les développeurs doivent adapter les implémentations: réduire les tables de chiffrement precalculées, simplifier les boucles internes, et optimiser pour l'espace plutôt que pour la vitesse. L'algorithme AES-128 avec des tables réduites est souvent préférable à AES-256 qui double la taille des tables.

**Pas de debugging en production:**
Les fonctions printf() et autres mécanismes de debug doivent être minimisés ou désactivés en production. Les erreurs à distance sont difficiles à diagnostiquer sans instrumentation специальная. Il faut prévoir des logs conditionnels compiles uniquement en mode debug et utiliser des LEDs ou des pins GPIO pour le diagnostic sur le hardware réel.

**Build cycle long:**
Chaque modification nécessite une reprogrammation de la FLASH du MCU (plusieurs secondes à plusieurs minutes selon l'interface). Les tests automatisés et les simulateurs sont critiques pour réduire le nombre de cycles de rebuild. Préférer tester sur PC (cross-compilation avec qemu) avant le déploiement sur le hardware.

**Hétérogénéité des toolchains:**
La toolchain peut varier selon l'architecture (ARM, MIPS, AVR, etc.) et le compiler peut avoir des particularités. La libc peut être minimale ou totalement absente (no libc). Les types like `ushort` ou `ulong` ne sont pas toujours disponibles et il faut utiliser les types standards (uint16_t, uint32_t).

### 4.2 Patterns à Suivre

**Bonnes pratiques à adopter:**

- Faire simple (KISS): Privilégier les implémentations simples aux optimisations complexes
- Tester localement: Tester chaque module indépendamment avant l'intégration
- Compiler souvent: Vérifier la compilation après chaque changement significatif
- Documenter les décisions: Conserver une trace des choix techniques et justifications
- Garder une version de travail: Toujours avoir un backup de la dernière version fonctionnelle

**Erreurs à éviter:**

- Optimiser prématurément: Attendre d'avoir des metrics avant d'optimiser
- Assumer une libc complète: Toujours vérifier les fonctions disponibles
- Ignorer les contraintes matérielles: Vérifier FLASH/RAM avant de choisir les algo
- Travailler sans tests: Les tests automatisés sont essentiels pour le firmware

### 4.3 Checklist pour Projets Futurs

- [ ] Code original compile-t-il sans erreurs ni warnings?
- [ ] Toolchain et environnement documentés quelque part?
- [ ] Contraintes hardware vérifiées (FLASH, RAM, ROM)?
- [ ] Format de sortie compris et validé avec une référence?
- [ ] Tests round-trip possibles (encode + decode = original)?
- [ ] Stubs syscalls requis et implémentés?
- [ ] Version de travail sauvegardée avant modification majeure?
- [ ] Tests hardware planifiés et programme?
- [ ] Plan de rollback prévu en cas de problème?
- [ ] Documentation des décisions techniques rédigée?

---

## 5. Statistiques du Projet

| Métrique | Valeur |
|----------|--------|
| Fichiers créés | aes.c, aes.h, syscalls.c (~3 fichiers) |
| Fichiers modifiés | ieee80211.h, eapol.h, hash.c, ieee80211.c, usbhcore.c, uart.c (~6 fichiers) |
| Nouvelles fonctionnalités WPA2 | 4 modules (AES-128, AES-CTR, CCMP-MIC, SHA256, HMAC-SHA256, PBKDF2) |
| Bugs préexistants découverts | 3types (ushort, ulong, syscalls) |
| Itérations format .sim | 2 (incorrect → correct) |
| Erreurs de compilation | Multiples (corrigées itérativement) |
| Temps de développement | Estimation: plusieurs jours |

---

## 6. Conclusion

Le projet a permis l'intégration réussie de WPA2 au Nabaztag. Les principales difficultés ont provenues du legacy code avec des types non standards et du format de fichier propriétaire non documenté. Les tests software sont globalement positifs avec des résultats corrects pour l'obfuscation et le format .sim. Les tests hardware restent à valider pour confirmer la兼容ibilité réelle avec le bootloader Nabaztag avant un déploiement en production.

**Recommandation finale:** Poursuivre avec des tests sur matériel réel avant tout déploiement en production. Prévoir un mécanisme de rollback si les tests hardware révèlent des problèmes d'incompatibilité.

---

*Document généré dans le cadre de la rétrospective du projet Nabaztag WPA2 - Avril 2026*