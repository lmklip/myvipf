import os, socket, requests, base64, json, urllib.parse, time, random
from concurrent.futures import ThreadPoolExecutor

# ВАШИ ДАННЫЕ
GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

# Настройки скорости и лимитов
THREADS = 200
TIMEOUT = 3.0  # Увеличиваем таймаут, учитывая возможные задержки в мобильной сети
MAX_FINAL = 50  # Выдаем 50 лучших серверов

# Список SNI, которые Мегафон/Yota боятся трогать (системный трафик)
TRUSTED_SNI = [
    "swscan.apple.com", "gateway.icloud.com", "itunes.apple.com",
    "updates.samsung.com", "download.windowsupdate.com", "dl.google.com",
    "connectivitycheck.gstatic.com", "graph.facebook.com"
]

def analyze_config(line):
    line = line.strip()
    if not line.startswith("vless://"): return None
    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)
        host, port = parsed.hostname, int(parsed.port) if parsed.port else 443
        security = str(query.get('security', [''])[0]).lower()
        sni = str(query.get('sni', [''])[0]).lower()
        fp = str(query.get('fp', [''])[0]).lower()
        flow = str(query.get('flow', [''])[0]).lower()
        transport = str(query.get('type', [''])[0]).lower()
        alpn = str(query.get('alpn', [''])[0]).lower()

        # 1. Reality/Vision - только они имеют шанс на Yota
        if security != "reality" and "vision" not in flow: return None
        
        score = 0
        # Огромный бонус за системный SNI
        if any(tsni in sni for tsni in TRUSTED_SNI): score += 5000
        # Бонус за gRPC (на мобилках топ)
        if transport == "grpc": score += 2000
        # Бонус за Vision (XTLS)
        if "vision" in flow: score += 1500
        # Бонус за отпечатки
        if fp in ["chrome", "safari", "edge"]: score += 1000
        # Бонус за ALPN
        if "h2" in alpn: score += 1000

        return {"host": host, "port": port, "score": score, "config": line}
    except Exception as e:
        print(f"Error processing config: {e}")
        return None

def check_alive(item):
    try:
        # Проверяем сервер через HTTPS, увеличиваем таймаут, чтобы учесть задержки
        response = requests.get(f"https://{item['host']}:{item['port']}", timeout=TIMEOUT)
        if response.status_code == 200:
            return item
    except requests.exceptions.RequestException:
        return None

def main():
    print("Запуск Mega-Mixer v11.0 (Yota CFO Optimized)...")
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        raw_lines = list(set(r.text.splitlines()))
    except Exception as e:
        print(f"Ошибка при скачивании конфигов: {e}")
        return

    # Анализ всех строк
    candidates = [analyze_config(l) for l in raw_lines if l]
    candidates = [c for c in candidates if c]

    print(f"Найдено {len(candidates)} кандидатов после фильтрации.")

    # Быстрая проверка доступности портов
    valid = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = list(executor.map(check_alive, candidates))
        valid = [v for v in results if v]

    print(f"Доступных серверов: {len(valid)}")

    # Фильтрация: 1 IP = 1 Самый лучший конфиг (убираем дубликаты портов)
    unique_ips = {}
    for v in valid:
        ip = v['host']
        if ip not in unique_ips or v['score'] > unique_ips[ip]['score']:
            unique_ips[ip] = v

    print(f"Уникальных IP: {len(unique_ips)}")

    # Сортировка по "пробивной способности"
    final_pool = list(unique_ips.values())
    final_pool.sort(key=lambda x: x['score'], reverse=True)

    # Берем топ-150 и из них перемешиваем 50 для ротации
    top_elite = final_pool[:150]
    if len(top_elite) > MAX_FINAL:
        final_selection = random.sample(top_elite, MAX_FINAL)
    else:
        final_selection = top_elite

    if not final_selection:
        print("Ничего не найдено.")
        return

    # Склеиваем и в Base64
    sub_text = "\n".join([s['config'] for s in final_selection])
    encoded_sub = base64.b64encode(sub_text.encode('utf-8')).decode('utf-8')

    # Записываем результат в файл
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print(f"УСПЕХ! В списке {len(final_selection)} уникальных защищенных узлов.")

if __name__ == "__main__":
    main()
