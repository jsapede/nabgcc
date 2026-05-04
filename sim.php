<?php
/**
 * sim.php — Génère le fichier .sim (firmware flashable) pour Nabaztag
 *
 * Usage: php sim.php
 * Prérequis: make (bin/Nab.bin doit exister)
 * Sortie: wpa2.sim
 */

$firmwarelimit = "-violet-";

// Table d'obfuscation (64 entrées)
$inv8 = array(
    4, 2, 18, 9, 36, 19, 13, 49, 52, 39, 33, 25, 14, 3, 22, 7,
    0, 30, 31, 58, 27, 54, 50, 57, 12, 47, 46, 55, 40, 11, 41, 48,
    51, 32, 43, 44, 16, 1, 28, 24, 17, 45, 6, 29, 42, 20, 10, 53,
    34, 21, 15, 5, 8, 26, 59, 60, 35, 56, 61, 37, 23, 38, 62, 63
);

function strcrypt8($str, $key, $alpha) {
    global $inv8;
    $o = "";
    for ($i = 0; $i < strlen($str); $i++) {
        $v = ord($str[$i]);
        $o .= chr(($alpha + ($v * $inv8[$key >> 1]) % 256));
        $key = (1 + 2 * $v) % 256;
    }
    return $o;
}

if (!file_exists("bin/Nab.bin")) {
    echo "ERREUR: bin/Nab.bin introuvable. Lancez 'make' d'abord.\n";
    exit(1);
}

$code = file_get_contents("bin/Nab.bin");
$size = strlen($code);
$obf = strcrypt8($code, 0x47, 47);

$hex = "";
for ($i = 0; $i < $size; $i++)
    $hex .= sprintf("%02x", ord($obf[$i]));

$sim = $firmwarelimit . sprintf("%08x", $size * 2) . $hex . $firmwarelimit;
file_put_contents("wpa2.simm", $sim);

echo "OK: wpa2.simm généré (" . strlen($sim) . " bytes)\n";
