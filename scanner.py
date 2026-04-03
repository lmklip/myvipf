import requests
import base64
import urllib.parse
import random
import sys

SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

MAX_FINAL = 50

TRUSTED_SNI = [
    "apple.com", "icloud.com", "itunes.apple.com",
    "windowsupdate.com", "dl.google.com",
    "gstatic.com", "facebook.com"
]


def safe_get(q, key):
    return q.get(key, [""])[0].lower()


def analyze(line):
    if not line.startswith("vless://"):
        return None

    try:
        p = urllib.parse.urlparse(line)
        q = urllib.parse.parse_qs(p.query)

        host = p.hostname
        if not host:
            return None

        security = safe_get(q, "security")
        sni = safe_get(q, "sni")
        fp = safe_get(q, "fp")
        flow = safe_get(q, "flow")
        net = safe_get(q, "type")

        score = 0

        if security == "reality":
            score += 4000

        if "vision" in flow:
            score += 3000

        if any(x in sni for x in TRUSTED_SNI):
            score += 3000

        if net == "grpc":
            score += 1500
        elif net == "ws":
            score += 800

        if fp in ["chrome", "safari", "edge"]:
            score += 1000

        return {
            "score": score,
            "host": host,
            "line": line
        }

    except:
        return None


def main():
    print("=== ANTI-DUP SMART FILTER ===")

    try:
        r = requests.get(SOURCE_URL, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print("Ошибка загрузки:", e)
        sys.exit(1)

    lines = list(set(r.text.splitlines()))
    print("Всего строк:", len(lines))

    parsed = []
    for l in lines:
        res = analyze(l)
        if res:
            parsed.append(res)

    print("После анализа:", len(parsed))

    if not parsed:
        print("ПУСТО")
        sys.exit(1)

    # 🔥 УБИРАЕМ ДУБЛИКАТЫ ПО IP
    unique = {}
    for item in parsed:
        ip = item["host"]
        if ip not in unique or item["score"] > unique[ip]["score"]:
            unique[ip] = item

    pool = list(unique.values())
    print("Уникальных IP:", len(pool))

    # сортировка
    pool.sort(key=lambda x: x["score"], reverse=True)

    # берем ТОЛЬКО верхнюю часть, но не маленькую
    top = pool[:300]

    # 🔥 СИЛЬНАЯ РАНДОМИЗАЦИЯ
    random.shuffle(top)

    final = top[:min(MAX_FINAL, len(top))]

    if not final:
        print("НЕТ РЕЗУЛЬТАТА")
        sys.exit(1)

    result = "\n".join([x["line"] for x in final])
    encoded = base64.b64encode(result.encode()).decode()

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded)

    print(f"ГОТОВО: {len(final)} серверов")


if __name__ == "__main__":
    main()
