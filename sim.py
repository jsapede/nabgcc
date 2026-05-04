#!/usr/bin/env python3
"""
sim.py — Génère le fichier .sim (firmware flashable) pour Nabaztag

Usage:
    python3 sim.py              # utilise bin/Nab.bin
    python3 sim.py chemin.bin   # utilise un binaire spécifique

Prérequis: make (bin/Nab.bin doit exister)
Sortie: Nabaztag_WPA2.si
"""

import sys, os

# Table d'obfuscation (64 entrées)
INV8 = [
    4, 2, 18, 9, 36, 19, 13, 49, 52, 39, 33, 25, 14, 3, 22, 7,
    0, 30, 31, 58, 27, 54, 50, 57, 12, 47, 46, 55, 40, 11, 41, 48,
    51, 32, 43, 44, 16, 1, 28, 24, 17, 45, 6, 29, 42, 20, 10, 53,
    34, 21, 15, 5, 8, 26, 59, 60, 35, 56, 61, 37, 23, 38, 62, 63
]

FIRMWARE_LIMIT = b"-violet-"


def strcrypt8(data: bytes, key: int, alpha: int) -> bytes:
    """Obfuscation crypt8 identique à l'originale."""
    out = bytearray()
    for v in data:
        idx = (key >> 1)
        factor = INV8[idx] if idx < len(INV8) else 0
        out.append((alpha + (v * factor)) % 256)
        key = (1 + 2 * v) % 256
    return bytes(out)


def make_sim(input_path: str, output_path: str):
    """Lit un binaire, obfusque, génère le .sim."""
    with open(input_path, "rb") as f:
        code = f.read()

    obf = strcrypt8(code, 0x47, 47)
    size_hex = f"{len(code) * 2:08x}"
    sim = FIRMWARE_LIMIT + size_hex.encode() + obf.hex().encode() + FIRMWARE_LIMIT

    with open(output_path, "wb") as f:
        f.write(sim)

    print(f"✅ {output_path} généré ({len(sim)} bytes / limite 256 KB)")


if __name__ == "__main__":
    input_path = sys.argv[1] if len(sys.argv) > 1 else "bin/Nab.bin"
    output_path = "Nabaztag_WPA2.si"

    if not os.path.exists(input_path):
        print(f"❌ {input_path} introuvable. Lancez 'make' d'abord.")
        sys.exit(1)

    make_sim(input_path, output_path)
