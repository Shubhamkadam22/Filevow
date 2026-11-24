"""Draw the FileVow app icon (design/app-icon.svg) as a multi-size .ico with Pillow."""

from __future__ import annotations

import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw

NAVY = (15, 42, 68, 255)
LIGHT = (230, 237, 245, 255)
BLUE = (110, 168, 224, 255)
SIZE = 1024  # draw large, then let Pillow downsample for each icon size


def hexagon(cx: float, cy: float, radius: float) -> list[tuple[float, float]]:
    return [(cx + radius * math.sin(math.radians(a)), cy - radius * math.cos(math.radians(a))) for a in range(0, 360, 60)]


def draw() -> Image.Image:
    unit = SIZE / 64
    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    canvas = ImageDraw.Draw(image)
    canvas.rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius=14 * unit, fill=NAVY)

    def at(value: float) -> float:  # the SVG's inner group: translate(9.6) scale(0.7)
        return (9.6 + value * 0.7) * unit

    centre = at(32)
    for radius, colour in ((28 * 0.7 * unit, LIGHT), (20 * 0.7 * unit, BLUE)):
        canvas.polygon(hexagon(centre, centre, radius), outline=colour, width=round(3.5 * 0.7 * unit))
    canvas.polygon(hexagon(centre, centre, 14 * 0.7 * unit), fill=LIGHT)
    tick = [(at(26), at(32.4)), (at(30.2), at(36.6)), (at(38.2), at(27.8))]
    canvas.line(tick, fill=NAVY, width=round(3.2 * 0.7 * unit), joint="curve")
    return image


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "filevow.ico")
    draw().save(target, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"wrote {target}")
