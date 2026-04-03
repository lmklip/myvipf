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
    
    try:
        if line.startswith("vmess://"):
            # VMess сейчас очень легко блокируется ТСПУ
            score -= 500
            data = line.split("vmess://")[1]
            missing_padding = len(data) % 4
            if missing_padding: data += '=' * (4 - missing_padding)
            obj = json.loads(base64.b64decode(data).decode('utf-8'))
            host, port = obj.get('add'), int(obj.get('port'))
            if port == 443: score += 100
        else:
            parsed = urllib.parse.urlparse(line)
            query = urllib.parse.parse_qs(parsed.query)
            
            host = parsed.hostname
            port = parsed.port
            if not port:
                netloc = parsed.netloc.split('@')[-1]
                if ':' in netloc: host, port = netloc.split(':')
                else: port = 443
            port = int(port)

            # --- СКОРИНГ (БАЛЛЫ ЗА СТОЙКОСТЬ К ТСПУ) ---
            # Ищем Reality (самый топ)
            if "reality" in str(query.get('security', '')).lower():
                score += 3000
            
            # XTLS / Vision
            if "vision" in str(query.get('flow', '')).lower():
                score += 2000
                
            # Маскировка под GRPC (хорошо для мобильных сетей)
            if "grpc" in str(query.get('type', '')).lower():
                score += 1000

            # Стандартный порт 443
            if port == 443:
                score += 500

        return host, port, score
    except:
        return None, None, -9999

def check_server(config_line):
    host, port, proto_score = analyze_config(config_line)
    if not host or proto_score < -1000: return None
    
    try:
        start = time.perf_counter()
        # Проверяем физическую доступность порта
        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency = (time.perf_counter() - start) * 1000
            # Итоговый балл: Больше баллов за протокол, меньше за пинг
            final_score = proto_score - latency
            return {"config": config_line, "score": final_score, "ms": latency}
    except:
        return None

def main():
    print("Запуск DPI-resistant сканера v2.0...")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        raw_lines = [l for l in response.text.splitlines() if l.strip()]
        print(f"Загружено {len(raw_lines)} конфигов из базы.")
    except Exception as e:
        print(f"Ошибка загрузки базы: {e}")
        return

    results = []
    print(f"Начинаю тесты в {THREADS} потоков...")
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        # Здесь была ошибка (check_worker), теперь исправлено на check_server
        futures = [executor.submit(check_server, line) for line in raw_lines]
        for f in futures:
            res = f.result()
            if res:
                results.append(res)

    # Сортируем: чем выше score, тем лучше сервер для обхода блокировок
    results.sort(key=lambda x: x['score'], reverse=True)
    final = results[:MAX_NODES]

    if not final:
        print("К сожалению, ни один сервер не прошел проверку."); return

    print(f"Отобрано {len(final)} устойчивых серверов.")
    
    # Кодируем в Base64 для файла подписки
    sub_text = "\n".join([r['config'] for r in final])
    encoded_sub = base64.b64encode(sub_text.encode('utf-8')).decode('utf-8')

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    # Генерируем QR-код на RAW ссылку (для удобства)
    qr = qrcode.make(RAW_URL)
    qr.save("subscription_qr.png")
    
    print(f"Успех! Подписка обновлена. Лучший пинг: {int(final[0]['ms'])}ms")

if __name__ == "__main__":
    main()
