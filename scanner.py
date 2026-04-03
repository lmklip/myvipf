import os, socket, requests, base64, json, urllib.parse, time
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
THREADS = 150 # Увеличиваем потоки для скорости
TIMEOUT = 1.0
MAX_NODES = 50

# Домены, которые MegaFon/Yota обычно "пропускает" без досмотра (CDN и Системные)
MEGAFON_WHITELIST = [
    "speedtest.net", "microsoft.com", "apple.com", "samsung.com",
    "vk.me", "yandex.net", "static.rustore.ru", "gosuslugi.ru"
]

def analyze_config_for_yota(line):
    """Специальный анализ конфига под MegaFon/Yota DPI"""
    line = line.strip()
    score = 0
    try:
        if not line.startswith("vless://"):
            return None, None, -9999 # Игнорируем всё кроме VLESS

        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)
        
        host = parsed.hostname
        port = int(parsed.port) if parsed.port else 443
        
        security = str(query.get('security', [''])[0]).lower()
        sni = str(query.get('sni', [''])[0]).lower()
        fp = str(query.get('fp', [''])[0]).lower()
        transport = str(query.get('type', [''])[0]).lower()
        flow = str(query.get('flow', [''])[0]).lower()

        # --- СИСТЕМА БАЛЛОВ (MegaFon Special) ---
        
        # 1. Reality - основа основ
        if security == "reality":
            score += 5000
        else:
            return None, None, -9999 # Без Reality на Yota делать нечего

        # 2. Маскировка SNI под разрешенные ресурсы
        if any(domain in sni for domain in MEGAFON_WHITELIST):
            score += 3000
        
        # 3. TLS Fingerprint (Важнейший параметр для Мегафона)
        if fp in ['chrome', 'safari', 'edge']:
            score += 2000
        
        # 4. Протокол Flow (Vision на мобилках часто лучше)
        if "vision" in flow:
            score += 1500
            
        # 5. Транспорт gRPC (проходит через DPI Мегафона как нативный апп-трафик)
        if transport == "grpc":
            score += 1200
        
        # 6. Порт 443 (стандарт HTTPS)
        if port == 443:
            score += 800

        return host, port, score
    except:
        return None, None, -9999

def check_server(config_line):
    host, port, yota_score = analyze_config_for_yota(config_line)
    if not host or yota_score < 5000: # Проходной балл только для Reality
        return None
    
    try:
        # Проверяем доступность порта
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return {"config": config_line, "score": yota_score}
    except:
        return None

def main():
    print("Запуск Yota-MegaFon Optimized Scanner v3.0...")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        raw_lines = list(set(response.text.splitlines()))
    except: return

    results = []
    # Параллельная проверка в 150 потоков
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_server, line) for line in raw_lines if line.strip()]
        for f in futures:
            res = f.result()
            if res: results.append(res)

    # Сортировка по весу (сначала самые защищенные)
    results.sort(key=lambda x: x['score'], reverse=True)
    final = results[:MAX_NODES]

    if not final:
        print("Подходящих серверов для Yota не найдено."); return

    # Формирование Base64 подписки
    sub_content = "\n".join([r['config'] for r in final])
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print(f"Готово! Отобрано {len(final)} профилей с высоким приоритетом Yota/MegaFon.")

if __name__ == "__main__":
    main()
