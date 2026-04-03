import os, socket, requests, base64, json, urllib.parse, qrcode, time
from concurrent.futures import ThreadPoolExecutor

# --- ВАШИ ДАННЫЕ ---
GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/sub.txt"

# --- НАСТРОЙКИ ---
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
THREADS = 100
MAX_NODES = 50

# Список "Белых" доменов РФ для обхода ТСПУ
WHITE_DOMAINS = [
    "gosuslugi.ru", "yandex.ru", "mail.ru", "vk.com", "ok.ru", 
    "avito.ru", "ozon.ru", "wildberries.ru", "sberbank.ru", "tinkoff.ru"
]

def analyze_config(line):
    """Глубокий анализ конфига на выживаемость в РФ"""
    line = line.strip()
    score = 0
    try:
        if line.startswith("vmess://"):
            score -= 1000 # VMess почти всегда летит в бан на мобильном инете
            data = line.split("vmess://")[1]
            missing_padding = len(data) % 4
            if missing_padding: data += '=' * (4 - missing_padding)
            obj = json.loads(base64.b64decode(data).decode('utf-8'))
            host, port = obj.get('add'), int(obj.get('port'))
            sni = obj.get('sni', '').lower()
            if any(domain in sni for domain in WHITE_DOMAINS): score += 2000
        else:
            parsed = urllib.parse.urlparse(line)
            query = urllib.parse.parse_qs(parsed.query)
            host = parsed.hostname
            port = int(parsed.port) if parsed.port else 443
            
            sni = str(query.get('sni', [''])[0]).lower()
            security = str(query.get('security', [''])[0]).lower()
            flow = str(query.get('flow', [''])[0]).lower()
            transport = str(query.get('type', [''])[0]).lower()

            # --- СКОРИНГ ---
            # 1. Проверка на "Белый прыжок" (SNI)
            if any(domain in sni for domain in WHITE_DOMAINS):
                score += 5000 # Огромный приоритет за российский SNI
            
            # 2. Проверка на Reality (Самый стойкий)
            if security == "reality":
                score += 4000
            
            # 3. Проверка на Vision (XTLS)
            if "vision" in flow:
                score += 2000
                
            # 4. Проверка на транспорт (GRPC лучше для мобил)
            if transport == "grpc":
                score += 1500
            elif transport == "h2":
                score += 1000

        return host, port, score
    except:
        return None, None, -9999

def check_server(config_line):
    host, port, proto_score = analyze_config(config_line)
    if not host or proto_score < 0: return None # Отсеиваем весь "мусор" сразу
    
    try:
        # Проверяем только жив ли порт в принципе
        with socket.create_connection((host, port), timeout=1.5):
            return {"config": config_line, "score": proto_score}
    except:
        return None

def main():
    print("Запуск интеллектуального фильтра 'Анти-ТСПУ'...")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        raw_lines = list(set(response.text.splitlines())) # Убираем дубликаты
    except: return

    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_server, line) for line in raw_lines if line.strip()]
        for f in futures:
            res = f.result()
            if res: results.append(res)

    # Сортируем: в топе будут те, у кого есть и Reality, и Русский SNI
    results.sort(key=lambda x: x['score'], reverse=True)
    final = results[:MAX_NODES]

    if not final:
        print("Ни одного стойкого сервера не найдено."); return

    print(f"Отобрано {len(final)} высокоустойчивых серверов.")
    
    sub_text = "\n".join([r['config'] for r in final])
    encoded_sub = base64.b64encode(sub_text.encode('utf-8')).decode('utf-8')

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    qr = qrcode.make(RAW_URL)
    qr.save("subscription_qr.png")
    print(f"Подписка обновлена. Ссылка: {RAW_URL}")

if __name__ == "__main__":
    main()
