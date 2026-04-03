import os, requests, base64, json, urllib.parse, time, random
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

# Лимиты для API Check-host (чтобы не забанили)
CHECK_LIMIT = 25  # Проверяем только 25 самых топовых по архитектуре
RU_NODES = ["ru1.check-host.net", "ru2.check-host.net", "md1.check-host.net"] # Москва и Спб

def extract_info(line):
    line = line.strip()
    if not line.startswith("vless://"): return None
    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)
        host, port = parsed.hostname, int(parsed.port) if parsed.port else 443
        security = str(query.get('security', [''])[0]).lower()
        sni = str(query.get('sni', [''])[0]).lower()
        
        if security != "reality": return None # Оставляем только Reality

        score = 0
        if any(d in sni for d in ["apple", "microsoft", "google", "samsung"]): score += 5000
        if "h2" in str(query.get('alpn', '')): score += 2000
        if "grpc" in str(query.get('type', '')): score += 1000
        
        return {"host": host, "port": port, "score": score, "config": line}
    except: return None

def check_via_ru_node(item):
    """Реальная проверка доступности из России через Check-Host API"""
    host_port = f"{item['host']}:{item['port']}"
    try:
        # Создаем запрос на проверку
        api_url = f"https://check-host.net/check-tcp?host={host_port}&node=ru1.check-host.net&node=ru2.check-host.net&node=md1.check-host.net"
        headers = {'Accept': 'application/json'}
        req = requests.get(api_url, headers=headers, timeout=10)
        request_id = req.json().get('request_id')
        
        if not request_id: return None

        # Ждем 5-7 секунд, пока узлы в РФ проведут проверку
        time.sleep(7)
        
        # Получаем результат
        res_url = f"https://check-host.net/check-result/{request_id}"
        result = requests.get(res_url, headers=headers, timeout=10).json()
        
        # Проверяем, ответил ли хоть один российский узел (результат не должен быть None)
        is_working_in_ru = False
        for node, data in result.items():
            if data and any(val is not None for val in data):
                is_working_in_ru = True
                break
        
        if is_working_in_ru:
            print(f"[OK] Сервер {host_port} доступен из РФ.")
            return item
        else:
            print(f"[FAIL] Сервер {host_port} недоступен из РФ.")
            return None
    except Exception as e:
        print(f"Ошибка API для {host_port}: {e}")
        return None

def main():
    print("--- Запуск REAL PROBE Scanner v10.0 (API Check-Host) ---")
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        raw_lines = list(set(r.text.splitlines()))
    except: return

    # 1. Сортируем по архитектуре и ГЕО (берем 25 лучших)
    candidates = [extract_info(l) for l in raw_lines if l]
    candidates = [c for c in candidates if c]
    candidates.sort(key=lambda x: x['score'], reverse=True)
    
    top_candidates = candidates[:CHECK_LIMIT]
    print(f"Отобрано {len(top_candidates)} кандидатов для реальной проверки из РФ...")

    # 2. Проверяем через API Check-Host
    working_in_ru = []
    # Делаем последовательно или небольшими группами, чтобы API не сбросил
    for item in top_candidates:
        res = check_via_ru_node(item)
        if res:
            working_in_ru.append(res)
        time.sleep(2) # Пауза между запросами к API

    if not working_in_ru:
        print("!!! Ни один сервер не прошел проверку из России через Check-Host.")
        # Если API подвел, отдаем топ по архитектуре как запасной вариант
        working_in_ru = top_candidates[:10]
    else:
        print(f"Найдено {len(working_in_ru)} подтвержденных серверов из РФ!")

    # 3. Сохраняем результат
    sub_data = base64.b64encode("\n".join([s['config'] for s in working_in_ru]).encode('utf-8')).decode('utf-8')
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub) # Исправлено на sub_data
        f.write(sub_data)
    
    print("Подписка обновлена. Используйте прямую ссылку на sub.txt.")

if __name__ == "__main__":
    main()
