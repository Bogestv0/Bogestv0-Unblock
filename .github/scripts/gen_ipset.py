#!/usr/bin/env python3
"""Обновляет автоматическую часть lists/ipset.txt: резолвит домены Discord и YouTube и копит их IPv4-адреса.
Записи старше 30 дней удаляются. Всё, что выше строки-маркера, — ручные записи, их скрипт не трогает."""
import datetime, os, re, socket, sys, time

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
OUT = os.path.join(ROOT, "lists", "ipset.txt")
MARK = "# --- АВТОМАТИЧЕСКИ (не редактировать ниже: файл обновляет GitHub Actions) ---"
KEEP_DAYS = 30
PREFIXES = ["", "www.", "gateway.", "cdn.", "media.", "images-ext-1.", "updates.", "dl.", "status.", "i.", "m."]
EXTRA = [
    "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net", "images-ext-1.discordapp.net",
    "dl.discordapp.net", "updates.discord.com", "discord-attachments-uploads-prd.storage.googleapis.com",
    "www.youtube.com", "m.youtube.com", "i.ytimg.com", "s.ytimg.com", "yt3.ggpht.com", "yt3.googleusercontent.com",
    "jnn-pa.googleapis.com", "redirector.googlevideo.com", "manifest.googlevideo.com", "youtubei.googleapis.com",
]


def domains():
    out = set(EXTRA)
    for name in ("discord.txt", "youtube.txt"):
        p = os.path.join(ROOT, "app", "lists", name)
        for line in open(p, encoding="utf-8"):
            d = line.split("#")[0].strip().lower()
            if not d or d.startswith("."):
                continue
            for pre in PREFIXES:
                out.add(pre + d)
    return sorted(out)


def resolve(host):
    fake = os.environ.get("GEN_FAKE_RESOLVE")  # для проверки скрипта: "host=ip,ip;host2=ip"
    if fake:
        for part in fake.split(";"):
            h, _, ips = part.partition("=")
            if h == host:
                return set(ips.split(","))
        return set()
    ips = set()
    for _ in range(3):  # ответы CDN вращаются — берём несколько раз
        try:
            for r in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM):
                ips.add(r[4][0])
        except OSError:
            break
        time.sleep(0.2)
    return ips


def private(ip):
    a = [int(x) for x in ip.split(".")]
    return a[0] in (0, 10, 127) or (a[0] == 172 and 16 <= a[1] <= 31) or (a[0] == 192 and a[1] == 168) or a[0] >= 224 or (a[0] == 169 and a[1] == 254)


def main():
    today = datetime.date.today()
    head, known = [], {}
    if os.path.exists(OUT):
        text = open(OUT, encoding="utf-8").read()
        before, _, after = text.partition(MARK)
        head = before.rstrip("\n").split("\n")
        for line in after.split("\n"):
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s*#\s*(\d{4}-\d{2}-\d{2})", line.strip())
            if m:
                known[m.group(1)] = datetime.date.fromisoformat(m.group(2))
    found = set()
    for d in domains():
        found |= {ip for ip in resolve(d) if not private(ip)}
    if not found and not known:
        print("ничего не найдено — файл не меняю")
        return 0
    for ip in found:
        known[ip] = today
    known = {ip: d for ip, d in known.items() if (today - d).days <= KEEP_DAYS}
    lines = head + ["", MARK]
    for ip in sorted(known, key=lambda s: tuple(int(x) for x in s.split("."))):
        lines.append(f"{ip}  # {known[ip].isoformat()}")
    new = "\n".join(lines) + "\n"
    old = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
    # дата последнего «увидел» меняется каждый день — пишем файл только если изменился набор адресов
    strip = lambda s: re.sub(r"\s*#\s*\d{4}-\d{2}-\d{2}", "", s)
    if strip(new) == strip(old):
        print("набор адресов не изменился")
        return 0
    open(OUT, "w", encoding="utf-8").write(new)
    print(f"обновлено: {len(known)} адресов (найдено сейчас: {len(found)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
