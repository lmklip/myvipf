import base64
import json
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ====== НАСТРОЙКИ ======

SOURCE_URL = "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt"

# Путь к xray/xray.exe. Можно переопределить переменной окружения XRAY_BIN.
XRAY_BIN = os.environ.get("XRAY_BIN", "xray.exe" if os.name == "nt" else "xray")

# Сколько потоков одновременно проверяют конфиги.
# 8-12 обычно разумно, потому что каждый worker запускает отдельный xray.
THREADS = 8

# Сколько держать попытку поднятия локального xray и прокси-проверки.
START_TIMEOUT = 3.0
PROBE_TIMEOUT = 6.0

# Максимум итоговых рабочих конфигов.
MAX_FINAL = 50

# Тестовые HTTPS-цели без DNS-зависимости: используем IP + SNI/Host.
TEST_ENDPOINTS = [
    ("1.1.1.1", 443, "one.one.one.one", "one.one.one.one", "/"),
    ("1.0.0.1", 443, "one.one.one.one", "one.one.one.one", "/"),
]

# Мягкий приоритет для сортировки перед проверкой.
TRUSTED_SNI = [
    "swscan.apple.com", "gateway.icloud.com", "itunes.apple.com",
    "updates.samsung.com", "download.windowsupdate.com", "dl.google.com",
    "connectivitycheck.gstatic.com", "graph.facebook.com"
]

# ====== УТИЛИТЫ ======

def qget(query, *names, default=""):
    for name in names:
        if name in query and query[name]:
            val = query[name][0]
            if val is not None:
                return val
    return default


def normalize_path(path: str) -> str:
    path = (path or "").strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    return path


def split_csv(value: str):
    value = (value or "").strip()
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:
            raise OSError("SOCKS5 reply truncated")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def stop_process(proc: subprocess.Popen):
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=1.0)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ====== ПАРСИНГ И ОЦЕНКА ======

def parse_vless(line: str):
    line = line.strip()
    if not line or not line.startswith("vless://"):
        return None

    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        host = parsed.hostname
        uuid = parsed.username
        if not host or not uuid:
            return None

        port = parsed.port or 443
        security = qget(query, "security", default="").lower().strip()
        sni = qget(query, "sni", "serverName", default="").strip()
        fp = qget(query, "fp", "fingerprint", default="").lower().strip()
        flow = qget(query, "flow", default="").strip()
        transport = qget(query, "type", "network", default="tcp").lower().strip()
        if transport in ("", "tcp"):
            transport = "raw"

        alpn = split_csv(qget(query, "alpn", default=""))
        ws_host = qget(query, "host", default="").strip()
        path = normalize_path(qget(query, "path", default=""))
        service_name = qget(query, "serviceName", "service", default="").strip()
        authority = qget(query, "authority", default="").strip()

        # REALITY поля, которые часто встречаются в подписках
        pbk = qget(query, "pbk", "publicKey", "password", default="").strip()
        sid = qget(query, "sid", "shortId", default="").strip()
        spx = qget(query, "spx", "spiderX", default="").strip()

        # Разрешаем пустой security: многие подписки уже содержат нужные параметры в transport/flow.
        item = {
            "raw": line,
            "uuid": uuid,
            "host": host,
            "port": int(port),
            "remark": urllib.parse.unquote(parsed.fragment or ""),
            "security": security,
            "sni": sni,
            "fp": fp,
            "flow": flow,
            "transport": transport,
            "alpn": alpn,
            "ws_host": ws_host,
            "path": path,
            "service_name": service_name,
            "authority": authority,
            "pbk": pbk,
            "sid": sid,
            "spx": spx,
        }
        item["score"] = score_item(item)
        return item
    except Exception:
        return None


def score_item(item) -> int:
    score = 0

    sni = (item.get("sni") or "").lower()
    transport = (item.get("transport") or "").lower()
    flow = (item.get("flow") or "").lower()
    fp = (item.get("fp") or "").lower()
    security = (item.get("security") or "").lower()
    alpn = [x.lower() for x in item.get("alpn", [])]

    if security == "reality":
        score += 3000
    if "vision" in flow:
        score += 1800
    if transport == "grpc":
        score += 2200
    elif transport == "ws":
        score += 1200
    elif transport == "httpupgrade":
        score += 900
    elif transport == "xhttp":
        score += 900
    elif transport == "raw":
        score += 500

    if any(tsni in sni for tsni in TRUSTED_SNI):
        score += 4000

    if fp in ("chrome", "safari", "edge", "ios", "android"):
        score += 900

    if "h2" in alpn:
        score += 700

    if item.get("pbk"):
        score += 200
    if item.get("sid"):
        score += 100

    return score


# ====== Xray JSON ======

def build_xray_config(item, socks_port: int):
    user = {
        "id": item["uuid"],
        "encryption": "none",
    }
    if item.get("flow"):
        user["flow"] = item["flow"]

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": item["host"],
                    "port": item["port"],
                    "users": [user],
                }
            ]
        },
        "streamSettings": {
            "network": item["transport"] if item["transport"] else "raw",
        },
    }

    security = (item.get("security") or "").lower()

    if security == "reality":
        outbound["streamSettings"]["security"] = "reality"
        reality = {}

        # Для REALITY в актуальной схеме Xray используется password
        # (прежнее publicKey), а также shortId и spiderX.
        server_name = item.get("sni") or item["host"]
        if server_name:
            reality["serverName"] = server_name
        if item.get("fp"):
            reality["fingerprint"] = item["fp"]
        if item.get("pbk"):
            reality["password"] = item["pbk"]
        if item.get("sid"):
            reality["shortId"] = item["sid"]
        if item.get("spx"):
            reality["spiderX"] = item["spx"]

        outbound["streamSettings"]["realitySettings"] = reality

    elif security == "tls":
        outbound["streamSettings"]["security"] = "tls"
        tls = {}
        server_name = item.get("sni") or item["host"]
        if server_name:
            tls["serverName"] = server_name
        if item.get("fp"):
            tls["fingerprint"] = item["fp"]
        if item.get("alpn"):
            tls["alpn"] = item["alpn"]
        outbound["streamSettings"]["tlsSettings"] = tls

    transport = item["transport"]

    if transport == "ws":
        ws = {}
        if item.get("path"):
            ws["path"] = item["path"]
        headers = {}
        if item.get("ws_host"):
            headers["Host"] = item["ws_host"]
        if headers:
            ws["headers"] = headers
        outbound["streamSettings"]["wsSettings"] = ws

    elif transport == "grpc":
        grpc = {}
        if item.get("service_name"):
            grpc["serviceName"] = item["service_name"]
        if item.get("authority"):
            grpc["authority"] = item["authority"]
        outbound["streamSettings"]["grpcSettings"] = grpc

    elif transport == "httpupgrade":
        hu = {}
        if item.get("path"):
            hu["path"] = item["path"]
        headers = {}
        if item.get("ws_host"):
            headers["Host"] = item["ws_host"]
        if headers:
            hu["headers"] = headers
        outbound["streamSettings"]["httpupgradeSettings"] = hu

    elif transport == "xhttp":
        xh = {}
        if item.get("path"):
            xh["path"] = item["path"]
        outbound["streamSettings"]["xhttpSettings"] = xh

    elif transport in ("raw", ""):
        # raw = алиас tcp
        pass

    config = {
        "log": {
            "loglevel": "none"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": False
                }
            }
        ],
        "outbounds": [outbound]
    }
    return config


# ====== SOCKS + HTTPS PROBE ======

def socks5_connect(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int, timeout: float) -> socket.socket:
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)

    # greeting: VER=5, NMETHODS=1, METHOD=0x00(no auth)
    s.sendall(b"\x05\x01\x00")
    resp = recv_exact(s, 2)
    if resp != b"\x05\x00":
        s.close()
        raise OSError(f"SOCKS auth rejected: {resp!r}")

    host_bytes = dest_host.encode("idna")
    if len(host_bytes) > 255:
        s.close()
        raise OSError("Destination host too long")

    # CONNECT by domain name
    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", dest_port)
    s.sendall(req)

    # reply: VER REP RSV ATYP BND.ADDR BND.PORT
    head = recv_exact(s, 4)
    if head[1] != 0x00:
        s.close()
        raise OSError(f"SOCKS CONNECT failed, REP={head[1]}")

    atyp = head[3]
    if atyp == 0x01:
        _ = recv_exact(s, 4)
    elif atyp == 0x03:
        ln = recv_exact(s, 1)[0]
        _ = recv_exact(s, ln)
    elif atyp == 0x04:
        _ = recv_exact(s, 16)
    _ = recv_exact(s, 2)

    return s


def https_probe_via_socks(proxy_port: int, dest_ip: str, dest_port: int, sni: str, host_header: str, path: str, timeout: float):
    raw = None
    tls = None
    try:
        raw = socks5_connect("127.0.0.1", proxy_port, dest_ip, dest_port, timeout)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        tls = ctx.wrap_socket(raw, server_hostname=sni)
        tls.settimeout(timeout)

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        tls.sendall(req.encode("utf-8"))

        data = b""
        while len(data) < 16384:
            chunk = tls.recv(1024)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break

        if not data:
            return False, "empty"

        first_line = data.split(b"\r\n", 1)[0].decode("latin1", "ignore")
        # Любая валидная HTTP-ответная строка = туннель прошёл.
        return first_line.startswith("HTTP/"), first_line

    except Exception as e:
        return False, str(e)
    finally:
        try:
            if tls is not None:
                tls.close()
        except Exception:
            pass
        try:
            if raw is not None:
                raw.close()
        except Exception:
            pass


# ====== Xray worker ======

def xray_binary_exists() -> bool:
    if os.path.isabs(XRAY_BIN) or os.path.sep in XRAY_BIN:
        return os.path.exists(XRAY_BIN)
    return shutil.which(XRAY_BIN) is not None


def check_item(item):
    socks_port = find_free_port()
    cfg = build_xray_config(item, socks_port)

    with tempfile.TemporaryDirectory(prefix="xray_scan_") as td:
        cfg_path = os.path.join(td, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            if not wait_for_port(socks_port, START_TIMEOUT):
                return None

            for dest_ip, dest_port, sni, host_header, path in TEST_ENDPOINTS:
                ok, status = https_probe_via_socks(
                    socks_port,
                    dest_ip,
                    dest_port,
                    sni,
                    host_header,
                    path,
                    PROBE_TIMEOUT,
                )
                if ok:
                    good = dict(item)
                    good["probe"] = status
                    return good

            return None

        finally:
            stop_process(proc)


# ====== MAIN ======

def main():
    print("Запуск scanner.py: проверка через локальный Xray и реальный HTTPS-probe")

    if not xray_binary_exists():
        print(f"Не найден Xray binary: {XRAY_BIN}")
        print("Положи xray/xray.exe в PATH или укажи переменную окружения XRAY_BIN.")
        return

    try:
        r = requests.get(SOURCE_URL, timeout=20)
        r.raise_for_status()
        raw_lines = list(set(r.text.splitlines()))
    except Exception as e:
        print(f"Не удалось скачать список: {e}")
        return

    candidates = []
    for line in raw_lines:
        item = parse_vless(line)
        if item:
            candidates.append(item)

    if not candidates:
        print("После парсинга не осталось ни одного VLESS-конфига.")
        return

    candidates.sort(key=lambda x: x["score"], reverse=True)
    print(f"Кандидатов после парсинга: {len(candidates)}")

    working = []
    seen = set()

    # Проверяем конфиги параллельно, но без перегруза: каждый worker поднимает свой xray.
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_item, item) for item in candidates]

        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception:
                result = None

            if not result:
                continue

            # Убираем дубликаты по точному конфигу
            key = result["raw"]
            if key in seen:
                continue

            seen.add(key)
            working.append(result)
            print(f"[OK] {len(working):02d}  {result.get('remark','').strip() or result['host']}  |  {result.get('probe','')}")
            if len(working) >= MAX_FINAL:
                # Уже достаточно
                break

    if not working:
        print("Ни одного реально рабочего конфига не найдено.")
        return

    # Сортируем рабочие по исходному score
    working.sort(key=lambda x: x["score"], reverse=True)

    final_selection = working[:MAX_FINAL]

    sub_text = "\n".join([x["raw"] for x in final_selection])
    encoded_sub = base64.b64encode(sub_text.encode("utf-8")).decode("utf-8")

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    with open("working_raw.txt", "w", encoding="utf-8") as f:
        f.write(sub_text)

    print(f"Готово. Найдено рабочих конфигов: {len(final_selection)}")
    print("Файлы: sub.txt (base64), working_raw.txt (обычный список)")


if __name__ == "__main__":
    main()
