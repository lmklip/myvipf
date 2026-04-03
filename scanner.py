import requests, base64, urllib.parse, random

SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

MAX_FINAL = 50

TRUSTED_SNI = [
    "swscan.apple.com", "gateway.icloud.com", "itunes.apple.com",
    "updates.samsung.com", "download.windowsupdate.com", "dl.google.com",
    "connectivitycheck.gstatic.com", "graph.facebook.com"
]

def analyze(line):
    if not line.startswith("vless://"):
        return None

    try:
        p = urllib.parse.urlparse(line)
        q = urllib.parse.parse_qs(p.query)

        security = q.get("security", [""])[0]
        sni = q.get("sni", [""])[0]
        fp = q.get("fp", [""])[0]
        flow = q.get("flow", [""])[0]
        net = q.get("type", [""])[0]

        score = 0

        # 💥 ОСНОВА (самое важное)
        if security == "reality":
            score += 5000

        if "vision" in flow:
            score += 3000

        # 💥 SNI (критично)
        if any(x in sni for x in TRUSTED_SNI):
            score += 4000

        # 💥 transport
        if net == "grpc":
            score += 2000
        if net == "ws":
            score += 1000

        # 💥 fingerprint
        if fp in ["chrome", "safari", "edge"]:
            score += 1500

        return (score, line)

    except:
        return None


def main():
    print("smart filter mode (без фейковых проверок)")

    r = requests.get(SOURCE_URL)
    lines = list(set(r.text.splitlines()))

    parsed = [analyze(l) for l in lines]
    parsed = [p for p in parsed if p]

    # сортировка
    parsed.sort(reverse=True)

    # берём топ 200 и мешаем
    top = parsed[:200]

    final = random.sample(top, min(MAX_FINAL, len(top)))

    result = "\n".join([x[1] for x in final])
    encoded = base64.b64encode(result.encode()).decode()

    with open("sub.txt", "w") as f:
        f.write(encoded)

    print(f"готово: {len(final)} серверов")

if __name__ == "__main__":
    main()
