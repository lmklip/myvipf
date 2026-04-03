import os, socket, requests, base64, json, urllib.parse, time, random
from concurrent.futures import ThreadPoolExecutor

GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
THREADS = 200
TIMEOUT = 1.0
MAX_NODES = 50

# Самые "неприкосновенные" домены для Мегафона/Yota (System-Level SNI)
SUPER_TRUST_SNI = [
    "gateway.icloud.com", "swscan.apple.com", "update.microsoft.com",
    "dl.google.com", "www.google-analytics.com", "graph.facebook.com"
]

def analyze_ultra_elite(line):
    line = line.strip()
    if not line.startswith("vless://"): return None
    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)
        host, port = parsed.hostname, int(parsed.port) if parsed.port else 443
        
        security = str(query.get('security', [''])[0]).lower()
        sni = str(query.get('sni', [''])[0]).lower()
        fp = str(query.get('fp', [''])[0]).lower()
        transport = str(query.get('type', [''])[0]).lower()
        flow = str(query.get('flow', [''])[0]).lower()
        alpn = str(query.get('alpn', [''])[0]).lower()

        score = 0
        # 1. Reality ОБЯЗАТЕЛЬНО
        if security != "reality": return None
        score += 10000

        # 2. Проверка на системный SNI (самый мощный бонус)
        if any(tsni in sni for tsni in SUPER_TRUST_SNI):
            score += 8000
        elif any(d in sni for d in ["yandex", "vk.com", "gosuslugi"]):
            score += 4000

        # 3. Транспорт gRPC (на мобильном инете Yota он "бессмертный")
        if transport == "grpc":
            score += 5000
        
        # 4. Fingerprint (Мегафон палит стандартные отпечатки)
        if fp in ["chrome", "safari", "edge"]:
            score += 2000
            
        # 5. Наличие ALPN h2 (критично для маскировки под HTTPS/2)
        if "h2" in alpn:
            score += 2000

        return {"host": host, "port": port, "score": score, "config": line}
    except: return None

def check_server(item):
    try:
        with socket.create_connection((item['host'], item['port']), timeout=TIMEOUT):
            return item
    except: return None

def main():
    print("Запуск DPI-Immunity Scanner v5.0 (Yota Special)...")
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        raw_lines = list(set(r.text.splitlines()))
    except: return

    candidates = [analyze_ultra_elite(l) for l in raw_lines if l.strip()]
    candidates = [c for c in candidates if c is not None]

    valid = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = list(executor.map(check_server, candidates))
        valid = [r for r in results if r is not None]

    # Уникальность по IP
    unique = {}
    for v in valid:
        if v['host'] not in unique or v['score'] > unique[v['host']]['score']:
            unique[v['host']] = v

    final = list(unique.values())
    final.sort(key=lambda x: x['score'], reverse=True)
    
    # Берем топ-100 и перемешиваем для "свежести"
    selection = final[:100]
    random.shuffle(selection)
    selection = selection[:MAX_NODES]

    if not selection: return

    sub = base64.b64encode("\n".join([s['config'] for s in selection]).encode('utf-8')).decode('utf-8')
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(sub)
    print(f"Готово! Найдено {len(selection)} элитных Reality-узлов.")

if __name__ == "__main__":
    main()
