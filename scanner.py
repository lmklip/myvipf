import requests
import base64
import urllib.parse
import random
import sys

SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

MAX_FINAL = 50

TRUSTED_SNI = [
    "swscan.apple.com", "gateway.icloud.com", "itunes.apple.com",
    "updates.samsung.com", "download.windowsupdate.com", "dl.google.com",
    "connectivitycheck.gstatic.com", "graph.facebook.com"
]


def safe_get(q, key):
    try:
        return q.get(key, [""])[0].lower()
    except:
        return ""


def analyze(line):
    if not line.startswith("vless://"):
        return None

    try:
        p = urllib.parse.urlparse(line)
        q = urllib.parse.parse_qs(p.query)

        security = safe_get(q, "security")
        sni = safe_get(q, "sni")
        fp = safe_get(q, "fp")
        flow = safe_get(q, "flow")
        net = safe_get(q, "type")

        score = 0

        # 🔥 ОСНОВА
        if security == "reality":
            score += 5000

        if "vision" in flow:
            score += 3000

        # 🔥 SNI
        if any(x in sni for x in TRUSTED_SNI):
            score += 4000

        # 🔥 transport
        if net == "grpc":
            score += 2000
        elif net == "ws":
            score += 1000

        # 🔥 fingerprint
        if fp in ["chrome", "safari", "edge"]:
            score += 1500

        # минимальный порог (важно!)
        if score < 3000:
            return None

        return (score, line)

    except Exception:
        return None


def main():
    print("=== SMART VLESS FILTER START ===")

    try:
        r = requests.get(SOURCE_URL, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print("Ошибка загрузки:", e)
        sys.exit(1)

    lines = list(set(r.text.splitlines()))

    print(f"Всего строк: {len(lines)}")

    parsed = []
    for l in lines:
        res = analyze(l)
        if res:
            parsed.append(res)

    print(f"После фильтра: {len(parsed)}")

    if not parsed:
        print("НЕТ подходящих конфигов")
        sys.exit(1)

    # сортировка по качеству
    parsed.sort(key=lambda x: x[0], reverse=True)

    # берем топ 200
    top = parsed[:200]

    # случайные 50 из лучших
    final = random.sample(top, min(MAX_FINAL, len(top)))

    result = "\n".join([x[1] for x in final])
    encoded = base64.b64encode(result.encode()).decode()

    try:
        with open("sub.txt", "w", encoding="utf-8") as f:
            f.write(encoded)
    except Exception as e:
        print("Ошибка записи файла:", e)
        sys.exit(1)

    print(f"ГОТОВО: {len(final)} серверов сохранено в sub.txt")


if __name__ == "__main__":
    main()
