"""Convert the PNGs from capture.cjs into the README's WebP images."""

import pathlib

from PIL import Image

here = pathlib.Path(__file__).parent
for png in sorted(here.glob("*.png")):
    image = Image.open(png).convert("RGB")
    image = image.resize((1440, round(image.height * 1440 / image.width)), Image.LANCZOS)
    image.save(png.with_suffix(".webp"), "WEBP", quality=82, method=6)
    png.unlink()
    print(png.with_suffix(".webp").name)
