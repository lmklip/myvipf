import os, requests, base64, json, urllib.parse, time, socket
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
GITHUB_USER = "lmklip"; GITHUB_REPO = "myvipf"
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

# Лимиты для стабильности
THREADS_GLOBAL = 100
CHECK_LIMIT_RU = 30   # Уменьшим до 30 для 100% стабильности API
THREADS_RU = 5        # Проверка по 5 штук, чтобы API не банил

def extract_info(line):
    line = line.strip()
    if not line.startswith("vless://"): return None
    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)
        # Оставляем только Reality
        if str(query.get('security', [''])[0]).lower() != "reality": return None
        
        host, port = parsed.hostname, int(parsed.port) if parsed.port else 443
        sni = str(query.get('sni', [''])[0]).lower()
        
        score = 0
        if any(d in sni for d in ["apple", "microsoft", "google", "samsung"]): score += 5000
        if "h2" in str(query.get('alpn', '')): score += 2000
        if "grpc" in str(query.get('type', '')): score += 1000
        return {"host": host, "port": port, "score": score, "config": line}
    except: return None

def check_fast_global(item):
    """Первичное сито: быстрая проверка порта"""
    try:
        with socket.create_connection((item['host'], item['port']), timeout=1.5):
            return item
    except: return None

def check_deep_ru(item):
    """Глубокая проверка из РФ (Check-Host API) с защитой от вылетов"""
    host_port = f"{item['host']}:{item['port']}"
    try:
        # 1. Запрос на проверку
        api_url = f"https://check-host.net/check-tcp?host={host_port}&node=ru1.check-host.net&node=ru2.check-host.net&node=md1.check-host.net"
        r = requests.get(api_url, headers={'Accept': 'application/json'}, timeout=15)
        if r.status_code != 200: return None
        
        req_data = r.json()
        request_id = req_data.get('request_id')
        if not request_id: return None

        time.sleep(10) # Даем узлам время на ответ
        
        # 2. Получение результата
        res_url = f"https://check-host.net/check-result/{request_id}"
        r_res = requests.get(res_url, timeout=15)
        if r_res.status_code != 200: return None
        
        result = r_res.json()
        if not result: return None
        
        # Анализ ответа российских узлов
        for node, data in result.items():
            if data and isinstance(data, list) and any(val is not None for val in data):
                print(f"[RU OK] {host_port}")
                return item
        return None
    except Exception as e:
        print(f"Ошибка API для {host_port}: {e}")
        return None

def main():
    print("--- ЗАПУСК СКАНЕРА v10.3 (Bulletproof) ---")
    try:
        r = requests.get(SOURCE_URL, timeout=20)
        raw_lines = list(set(r.text.splitlines()))
        print(f"Загружено: {len(raw_lines)} строк.")
    except Exception as e:
        print(f"Ошибка загрузки базы: {e}")
        return

    # ЭТАП 1: Реалити-фильтр
    candidates = [extract_info(l) for l in raw_lines if l]
    candidates = [c for c in candidates if c]
    print(f"Reality-кандидатов: {len(candidates)}")

    # ЭТАП 2: Быстрый TCP чек (Глобальный)
    live_globally = []
    with ThreadPoolExecutor(max_workers=THREADS_GLOBAL) as executor:
        res_glob = list(executor.map(check_fast_global, candidates))
        live_globally = [r for r in res_glob if r]
    
    live_globally.sort(key=lambda x: x['score'], reverse=True)
    finalists = live_globally[:CHECK_LIMIT_RU]
    print(f"Живых в мире: {len(live_globally)}. Проверка {len(finalists)} финалистов через РФ...")

    if not finalists:
        print("Нет живых серверов для проверки.")
        return

    # ЭТАП 3: Проверка через Россию (Check-Host)
    confirmed_in_ru = []
    with ThreadPoolExecutor(max_workers=THREADS_RU) as executor:
        res_ru = list(executor.map(check_deep_ru, finalists))
        confirmed_in_ru = [r for r in res_ru if r]

    # Если через РФ ничего не нашлось, берем топ по архитектуре (чтобы файл не был пустым)
    if not confirmed_in_ru:
        print("РФ-узлы не подтвердили доступность. Использую запасной Топ-10.")
        confirmed_in_ru = finalists[:10]

    # Сохранение результата (Base64)
    final_configs = [s['config'] for s in confirmed_in_ru]
    sub_data = base64.b64encode("\n".join(final_configs).encode('utf-8')).decode('utf-8')
    
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(sub_data)
    
    print(f"--- ГОТОВО! В подписке {len(confirmed_in_ru)} серверов. ---")

if __name__ == "__main__":
    main()
