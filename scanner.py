import os
import socket
import requests
import base64
import json
import urllib.parse
import qrcode
import time
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ВАШЕГО ГИТА ---
GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/sub.txt"

# --- НАСТРОЙКИ ОПТИМИЗАЦИИ ---
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
THREADS = 100
TIMEOUT = 1.5         # Строгий отбор: только очень быстрые серверы
MAX_FINAL_NODES = 50  # Оставляем ровно 50 лучших

def extract_host_port(line):
    line = line.strip()
    if not line or "://" not in line: return None
    try:
        if line.startswith("vmess://"):
            data = line.split("vmess://")[1]
            missing_padding = len(data) % 4
            if missing_padding: data += '=' * (4 - missing_padding)
            obj = json.loads(base64.b64decode(data).decode('utf-8'))
            return obj.get('add'), int(obj.get('port'))
        else:
            parsed = urllib.parse.urlparse(line)
            host, port = parsed.hostname, parsed.port
            if not port:
                netloc = parsed.netloc.split('@')[-1]
                if ':' in netloc: host, port = netloc.split(':')
            return host, int(port)
    except: return None

def check_server(config_line):
    hp = extract_host_port(config_line)
    if not hp: return None
    host, port = hp
    
    # Вес для портов (приоритет 443 и 80 для обхода фильтров сетей)
    priority_bonus = 0
    if port in [443, 80, 8080, 8443]:
        priority_bonus = 100 # Делаем их "виртуально быстрее" для сортировки

    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency = (time.perf_counter() - start) * 1000
            # Итоговый "балл" сервера: задержка минус бонус порта
            return {"config": config_line, "latency": latency - priority_bonus, "real_ms": latency}
    except:
        return None

def main():
    print(f"--- ЗАПУСК ОПТИМИЗИРОВАННОГО СКАНЕРА ---")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        all_lines = [l for l in response.text.splitlines() if l.strip()]
    except:
        print("Ошибка сети"); return

    print(f"Сканирую {len(all_lines)} конфигов. Цель: выбрать Топ-50...")
    
    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_server, line) for line in all_lines]
        for f in futures:
            res = f.result()
            if res: results.append(res)

    # Сортируем по "баллу" (учитываем и скорость, и стандартность порта)
    results.sort(key=lambda x: x['latency'])
    
    # Оставляем ровно Топ-50
    final_selection = results[:MAX_FINAL_NODES]
    
    if not final_selection:
        print("!!! Не найдено серверов, отвечающих строгим критериям."); return

    # Формируем подписку
    print(f"Отобрано {len(final_selection)} элитных серверов.")
    working_configs = "\n".join([r['config'] for r in final_selection])
    encoded_sub = base64.b64encode(working_configs.encode('utf-8')).decode('utf-8')

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    # QR-код на RAW ссылку
    qr = qrcode.make(RAW_URL)
    qr.save("subscription_qr.png")
    
    print(f"Подписка обновлена. Пинг лучших: {int(final_selection[0]['real_ms'])}ms")

if __name__ == "__main__":
    main()
