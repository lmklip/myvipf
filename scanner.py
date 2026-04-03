import requests
import socket
import time
import re
import urllib.parse
import base64
import json
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
OUTPUT_FILE = "top_20_configs.txt"
MAX_WORKERS = 100  # Скорость сканирования (количество потоков)
TIMEOUT = 3.0      # Таймаут ожидания ответа

def parse_vmess(config):
    try:
        data = config.split("vmess://")[1]
        decoded = base64.b64decode(data).decode('utf-8')
        obj = json.loads(decoded)
        return obj.get('add'), int(obj.get('port'))
    except: return None

def get_host_port(line):
    line = line.strip()
    if not line: return None
    if line.startswith("vmess://"):
        return parse_vmess(line)
    try:
        parsed = urllib.parse.urlparse(line)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port
    except: return None

def check_server(config_line):
    target = get_host_port(config_line)
    if not target:
        return None
    
    host, port = target
    start_time = time.perf_counter()
    try:
        # Проверка реальной доступности порта (TCP Handshake)
        with socket.create_connection((host, port), timeout=TIMEOUT):
            delay = (time.perf_counter() - start_time) * 1000
            return {"line": config_line, "delay": delay}
    except:
        return None

def main():
    print("Загрузка конфигов...")
    raw_data = requests.get(SOURCE_URL).text.splitlines()
    
    results = []
    print(f"Сканирование {len(raw_data)} серверов в {MAX_WORKERS} потоков...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Запускаем проверку всех строк параллельно
        future_to_config = {executor.submit(check_server, line): line for line in raw_data}
        for future in future_to_config:
            res = future.result()
            if res:
                results.append(res)

    # Сортируем по задержке (от меньшей к большей)
    results.sort(key=lambda x: x['delay'])
    
    # Берем топ 20
    top_20 = [r['line'] for r in results[:20]]
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(top_20))
    
    print(f"Готово! Найдено рабочих: {len(results)}. Топ-20 записаны в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()