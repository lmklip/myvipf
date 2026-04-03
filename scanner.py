import os
import socket
import requests
import base64
import json
import urllib.parse
import qrcode
import time
from concurrent.futures import ThreadPoolExecutor

# --- ВАШИ ДАННЫЕ ---
GITHUB_USER = "lmklip"
GITHUB_REPO = "myvipf"
RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/sub.txt"

# --- НАСТРОЙКИ ФИЛЬТРАЦИИ ---
SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"
THREADS = 100
TIMEOUT = 1.0         # Только самые отзывчивые
MAX_NODES = 50

def analyze_config(line):
    """Анализирует тип протокола и его защиту от DPI"""
    line = line.strip()
    score = 0
    params = {}
    
    try:
        if line.startswith("vmess://"):
            # VMess сейчас очень легко блокируется, даем низкий приоритет
            score -= 500
            data = line.split("vmess://")[1]
            missing_padding = len(data) % 4
            if missing_padding: data += '=' * (4 - missing_padding)
            obj = json.loads(base64.b64decode(data).decode('utf-8'))
            host, port = obj.get('add'), int(obj.get('port'))
            # Если VMess на 443 порту - чуть лучше
            if port == 443: score += 100
        else:
            parsed = urllib.parse.urlparse(line)
            query = urllib.parse.parse_qs(parsed.query)
            
            # Извлекаем хост и порт
            host = parsed.hostname
            port = parsed.port
            if not port:
                netloc = parsed.netloc.split('@')[-1]
                if ':' in netloc: host, port = netloc.split(':')
                else: port = 443 # По умолчанию
            port = int(port)

            # --- СКОРИНГ (БАЛЛЫ ЗА СТОЙКОСТЬ) ---
            # Самый топ: VLESS + Reality
            if "reality" in str(query.get('security', '')).lower():
                score += 2000
            
            # VLESS + Vision (XTLS)
            if "vision" in str(query.get('flow', '')).lower():
                score += 1500
                
            # Маскировка под GRPC (хорошо на мобильных сетях)
            if "grpc" in str(query.get('type', '')).lower():
                score += 800

            # Стандартный TLS на 443 порту
            if port == 443:
                score += 300

        return host, port, score
    except:
        return None, None, -9999

def check_server(config_line):
    host, port, proto_score = analyze_config(config_line)
    if not host or proto_score < -1000: return None
    
    try:
        start = time.perf_counter()
        # Проверяем доступность порта
        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency = (time.perf_counter() - start) * 1000
            # Итоговый балл: Больше баллов за протокол, меньше за пинг
            final_score = proto_score - latency
            return {"config": config_line, "score": final_score, "ms": latency}
    except:
        return None

def main():
    print("Запуск DPI-resistant сканера...")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        raw_lines = [l for l in response.text.splitlines() if l.strip()]
    except: return

    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_worker, line) for line in raw_lines] # Исправил check_worker на check_server
        futures = [executor.submit(check_server, line) for line in raw_lines]
        for f in futures:
            res = f.result()
            if res: results.append(res)

    # Сортируем: чем выше score, тем лучше сервер для обхода блокировок
    results.sort(key=lambda x: x['score'], reverse=True)
    final = results[:MAX_NODES]

    if not final:
        print("Ничего не найдено."); return

    sub_text = "\n".join([r['config'] for r in final])
    encoded_sub = base64.b64encode(sub_text.encode('utf-8')).decode('utf-8')

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    qr = qrcode.make(RAW_URL)
    qr.save("subscription_qr.png")
    
    print(f"Обновлено! Найдено {len(final)} устойчивых серверов.")

if __name__ == "__main__":
    main()
