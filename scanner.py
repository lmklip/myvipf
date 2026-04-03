import os, socket, requests, base64, json, urllib.parse, time, random
from concurrent.futures import ThreadPoolExecutor

# --- ВАШИ ДАННЫЕ ---
GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"

# --- НАСТРОЙКИ ---
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
THREADS = 150
TIMEOUT = 1.2
MAX_NODES = 50

# Домены, маскировка под которые лучше всего пробивает ТСПУ Мегафона/Yota
HIGH_TRUST_SNI = [
    "download.windowsupdate.com", "itunes.apple.com", "updates.samsung.com",
    "connectivitycheck.gstatic.com", "cdn.discordapp.com", "microsoft.com"
]

def analyze_for_yota_elite(line):
    line = line.strip()
    if not line.startswith("vless://"): return None
    
    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)
        
        host = parsed.hostname
        port = int(parsed.port) if parsed.port else 443
        
        # Параметры маскировки
        security = str(query.get('security', [''])[0]).lower()
        sni = str(query.get('sni', [''])[0]).lower()
        fp = str(query.get('fp', [''])[0]).lower()
        type_ = str(query.get('type', [''])[0]).lower()
        flow = str(query.get('flow', [''])[0]).lower()
        alpn = str(query.get('alpn', [''])[0]).lower()

        # --- КРИТЕРИИ ОТБОРА (ТОЛЬКО РЕАЛЬНЫЙ ОБХОД ТСПУ) ---
        score = 0
        
        # 1. Reality - БЕЗ НЕГО ДАЖЕ НЕ СМОТРИМ
        if security != "reality":
            return None 
        score += 5000

        # 2. Правильный SNI (самый важный фактор для прыжка через белый список)
        if any(target in sni for target in HIGH_TRUST_SNI):
            score += 3000
        elif any(domain in sni for domain in ["yandex", "mail.ru", "vk.com", "gosuslugi"]):
            score += 2000 # Российские сервисы тоже хорошо

        # 3. Наличие ALPN (HTTP/2) - Мегафон очень не любит VPN без этого
        if "h2" in alpn:
            score += 1500
        
        # 4. Fingerprint (Браузерный отпечаток)
        if fp in ["chrome", "safari", "edge"]:
            score += 1000
            
        # 5. Тип транспорта (gRPC на Yota живет дольше)
        if type_ == "grpc":
            score += 1200
        elif type_ == "ws":
            score -= 500 # WebSocket на мобилках сейчас часто палится

        return {"host": host, "port": port, "score": score, "config": line}
    except:
        return None

def check_server(item):
    try:
        # Просто проверяем, не забанен ли IP на уровне порта (хотя это не гарантия)
        with socket.create_connection((item['host'], item['port']), timeout=TIMEOUT):
            return item
    except:
        return None

def main():
    print("Запуск Elite Yota-MegaFon Scanner v4.0...")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        raw_lines = list(set(response.text.splitlines()))
    except: return

    # Шаг 1: Первичный анализ и скоринг
    candidates = []
    for line in raw_lines:
        analyzed = analyze_for_yota_elite(line)
        if analyzed:
            candidates.append(analyzed)

    # Шаг 2: Тестирование в потоках
    valid_results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_server, c) for c in candidates]
        for f in futures:
            res = f.result()
            if res: valid_results.append(res)

    # Шаг 3: Фильтр по уникальности хостов (чтобы не было 50 раз одного и того же сервера)
    unique_hosts = {}
    for item in valid_results:
        h = item['host']
        # Если хост уже есть, оставляем тот, у которого score выше
        if h not in unique_hosts or item['score'] > unique_hosts[h]['score']:
            unique_hosts[h] = item

    final_list = list(unique_hosts.values())
    
    # Шаг 4: Сортировка по баллу + легкий рандом для ротации
    # (Берем топ-100 и перемешиваем, чтобы каждый раз были новые кандидаты)
    final_list.sort(key=lambda x: x['score'], reverse=True)
    
    top_selection = final_list[:100] # Берем 100 лучших по архитектуре
    random.shuffle(top_selection)    # Перемешиваем
    final_selection = top_selection[:MAX_NODES] # Оставляем 50

    if not final_selection:
        print("Подходящих Reality-серверов не найдено."); return

    # Сохранение
    sub_content = "\n".join([r['config'] for r in final_selection])
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print(f"Готово! Найдено {len(final_selection)} уникальных Reality-узлов.")

if __name__ == "__main__":
    main()
