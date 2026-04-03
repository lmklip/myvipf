import os, socket, requests, base64, json, urllib.parse, time
from concurrent.futures import ThreadPoolExecutor

GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

THREADS = 100
TIMEOUT = 1.0 # Только базовый чек на то, что сервер не "кирпич"
MAX_NODES = 50

# Домены, маскировка под которые лучше всего пробивает DPI Мегафона/Yota
WHITELIST_SNI = [
    "speedtest.net", "microsoft.com", "apple.com", "updates.samsung.com",
    "gosuslugi.ru", "yandex.ru", "vk.me", "ok.ru", "static.rustore.ru"
]

def analyze_dpi_resistance(line):
    """Оценивает вероятность обхода ТСПУ по параметрам конфига"""
    line = line.strip()
    if not line.startswith("vless://"): return None
    
    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)
        host, port = parsed.hostname, int(parsed.port) if parsed.port else 443
        
        security = str(query.get('security', [''])[0]).lower()
        sni = str(query.get('sni', [''])[0]).lower()
        fp = str(query.get('fp', [''])[0]).lower()
        alpn = str(query.get('alpn', [''])[0]).lower()
        flow = str(query.get('flow', [''])[0]).lower()
        transport = str(query.get('type', [''])[0]).lower()

        # 1. Reality ОБЯЗАТЕЛЬНО. Без него на Йоту не идем.
        if security != "reality": return None
        
        score = 0
        # 2. Маскировка SNI (Прыжок через белый список)
        if any(domain in sni for domain in WHITELIST_SNI): score += 5000
        # 3. Наличие Vision (XTLS)
        if "vision" in flow: score += 2000
        # 4. Fingerprint (uTLS - маскировка под браузер)
        if fp in ["chrome", "safari", "edge", "firefox"]: score += 1500
        # 5. ALPN h2 (маскировка под HTTP/2 трафик)
        if "h2" in alpn: score += 1500
        # 6. gRPC (лучший транспорт для мобильных сетей)
        if transport == "grpc": score += 1000

        return {"host": host, "port": port, "score": score, "config": line}
    except: return None

def check_alive(item):
    """Проверка, что сервер вообще живой (хотя бы порт открыт)"""
    try:
        with socket.create_connection((item['host'], item['port']), timeout=TIMEOUT):
            return item
    except: return None

def main():
    print("Запуск DPI-Resistance Quality Scanner v8.0...")
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        raw_lines = list(set(r.text.splitlines()))
    except: return

    # Анализируем архитектуру конфигов
    candidates = [analyze_dpi_resistance(l) for l in raw_lines if l]
    candidates = [c for c in candidates if c]

    # Быстрый чек на "живость"
    valid = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = list(executor.map(check_alive, candidates))
        valid = [r for r in results if r]

    # СТРАТЕГИЯ КАЧЕСТВА: 1 IP = 1 Лучший конфиг
    unique_nodes = {}
    for v in valid:
        ip = v['host']
        if ip not in unique_nodes or v['score'] > unique_nodes[ip]['score']:
            unique_nodes[ip] = v

    # Сортируем по баллам качества (архитектуре), а не по пингу
    final_selection = list(unique_nodes.values())
    final_selection.sort(key=lambda x: x['score'], reverse=True)
    
    # Берем ТОП-50
    final_selection = final_selection[:MAX_NODES]

    if not final_selection:
        print("Ни одного Reality-сервера не найдено."); return

    # Формируем подписку
    sub_data = base64.b64encode("\n".join([s['config'] for s in final_selection]).encode('utf-8')).decode('utf-8')
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(sub_data)
    
    print(f"Готово! Отобрано {len(final_selection)} уникальных Reality-узлов с лучшей архитектурой.")

if __name__ == "__main__":
    main()
