#!/usr/bin/env python3
"""Shrink screenshots in place: quantise to a 256-colour palette and re-save as optimised PNG.

usage: optimize.py <src-dir> <dest-dir>
"""
import sys
from pathlib import Path

from PIL import Image

src, dest = Path(sys.argv[1]), Path(sys.argv[2])
dest.mkdir(parents=True, exist_ok=True)
for png in sorted(src.glob("*.png")):
    image = Image.open(png).convert("RGB").quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    target = dest / png.name
    image.save(target, optimize=True)
    print(f"{png.name}: {target.stat().st_size // 1024} KB")
