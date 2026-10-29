#!/usr/bin/env python3
"""Собирает Windows-ресурс с иконкой (.syso) из app/icon.ico — без внешних утилит.

    python3 tools/make_syso.py app/icon.ico app/rsrc_windows_amd64.syso installer/rsrc_windows_amd64.syso

Go сам подхватывает *_windows_amd64.syso при сборке, и иконка попадает внутрь .exe
(ярлыки, «Пуск», панель задач и проводник берут её оттуда, а не из отдельного .ico).
Нужен Pillow (pip install pillow).
"""
import io
import struct
import sys

from PIL import Image


def icon_images(path):
    """[(w, h, данные RT_ICON)] — 256 px храним как PNG, остальные как классический BMP (DIB)."""
    im = Image.open(path)
    out = []
    for w, h in sorted(im.info["sizes"]):
        fr = im.ico.getimage((w, h)).convert("RGBA")
        if w >= 256:
            b = io.BytesIO()
            fr.save(b, "PNG")
            out.append((w, h, b.getvalue()))
            continue
        px = fr.load()
        rows = []
        for y in range(h - 1, -1, -1):  # BMP хранится снизу вверх, BGRA
            rows.append(b"".join(struct.pack("BBBB", px[x, y][2], px[x, y][1], px[x, y][0], px[x, y][3]) for x in range(w)))
        mask_row = b"\0" * (((w + 31) // 32) * 4)  # AND-маска: всё видимое, прозрачность — в альфа-канале
        hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
        out.append((w, h, hdr + b"".join(rows) + mask_row * h))
    return out


def build(images):
    # дерево каталогов: тип -> id -> язык -> данные
    icons = [(i + 1, d) for i, (_, _, d) in enumerate(images)]
    grp = struct.pack("<HHH", 0, 1, len(images))
    for i, (w, h, d) in enumerate(images):
        grp += struct.pack("<BBBBHHIH", 0 if w >= 256 else w, 0 if h >= 256 else h, 0, 0, 1, 32, len(d), i + 1)
    types = [(3, icons), (14, [(1, grp)])]  # RT_ICON, RT_GROUP_ICON (по возрастанию)

    def dir_size(n):
        return 16 + 8 * n

    # раскладка: корень, каталоги типов, каталоги id, каталоги языков, записи данных, сами данные
    pos = dir_size(len(types))
    type_dir = []
    for _, items in types:
        type_dir.append(pos)
        pos += dir_size(len(items))
    id_dir = {}
    for t, (_, items) in enumerate(types):
        for rid, _ in items:
            id_dir[(t, rid)] = pos
            pos += dir_size(1)
    entries = {}
    for t, (_, items) in enumerate(types):
        for rid, _ in items:
            entries[(t, rid)] = pos
            pos += 16
    data_pos = {}
    blobs = b""
    for t, (_, items) in enumerate(types):
        for rid, d in items:
            data_pos[(t, rid)] = pos + len(blobs)
            blobs += d + b"\0" * (-len(d) % 4)

    def table(n_id, entries_):
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, n_id) + b"".join(struct.pack("<II", i, o) for i, o in entries_)

    raw = table(len(types), [(tid, 0x80000000 | type_dir[t]) for t, (tid, _) in enumerate(types)])
    for t, (_, items) in enumerate(types):
        raw += table(len(items), [(rid, 0x80000000 | id_dir[(t, rid)]) for rid, _ in items])
    for t, (_, items) in enumerate(types):
        for rid, _ in items:
            raw += table(1, [(0x0409, entries[(t, rid)])])
    relocs = []
    for t, (_, items) in enumerate(types):
        for rid, d in items:
            relocs.append(len(raw))  # смещение поля OffsetToData (RVA) — его заполнит компоновщик
            raw += struct.pack("<IIII", data_pos[(t, rid)], len(d), 1252, 0)
    raw += blobs
    return raw, relocs


def coff(raw, relocs):
    n = len(relocs)
    sec_off = 20 + 40
    reloc_off = sec_off + len(raw)
    sym_off = reloc_off + 10 * n
    fh = struct.pack("<HHIIIHH", 0x8664, 1, 0, sym_off, 2, 0, 0)
    sh = struct.pack("<8sIIIIIIHHI", b".rsrc", 0, 0, len(raw), sec_off, reloc_off, 0, n, 0, 0x40000040)
    rel = b"".join(struct.pack("<IIH", o, 0, 3) for o in relocs)  # IMAGE_REL_AMD64_ADDR32NB к символу .rsrc
    sym = struct.pack("<8sIhHBB", b".rsrc", 0, 1, 0, 3, 1) + struct.pack("<IHHIHBBBB", len(raw), n, 0, 0, 0, 0, 0, 0, 0)[:18]
    return fh + sh + raw + rel + sym + struct.pack("<I", 4)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    obj = coff(*build(icon_images(sys.argv[1])))
    for p in sys.argv[2:]:
        open(p, "wb").write(obj)
        print("ok:", p, len(obj), "байт")
