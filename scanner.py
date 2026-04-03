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

# --- НАСТРОЙКИ СКАНЕРА ---
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
THREADS = 100
TIMEOUT = 2.0

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
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency = (time.perf_counter() - start) * 1000
            return {"config": config_line, "latency": latency}
    except: return None

def main():
    print(f"Загрузка базы конфигов...")
    response = requests.get(SOURCE_URL, timeout=15)
    all_lines = [l for l in response.text.splitlines() if l.strip()]
    
    print(f"Тестирую {len(all_lines)} серверов...")
    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_server, line) for line in all_lines]
        for f in futures:
            res = f.result()
            if res: results.append(res)

    results.sort(key=lambda x: x['latency'])
    
    # Формируем файл подписки (Base64)
    # Берем ВСЕ рабочие (в подписке нет лимита на размер)
    working_configs = "\n".join([r['config'] for r in results])
    encoded_sub = base64.b64encode(working_configs.encode('utf-8')).decode('utf-8')

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    # Генерируем QR-код на ссылку RAW
    qr = qrcode.make(RAW_URL)
    qr.save("subscription_qr.png")
    
    print(f"Готово! Найдено рабочих: {len(results)}")
    print(f"Ссылка на подписку: {RAW_URL}")

if __name__ == "__main__":
    main()
