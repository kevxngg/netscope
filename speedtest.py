"""
speedtest.py - Test de velocidad de internet (latencia, descarga, subida).

Usa los endpoints publicos de medicion de Cloudflare (speed.cloudflare.com).
Solo libreria estandar (urllib), sin dependencias extra.
"""

import time
import urllib.request

DOWN_URL = "https://speed.cloudflare.com/__down?bytes={}"
UP_URL = "https://speed.cloudflare.com/__up"
UA = {"User-Agent": "NetScope/1.0"}


def _latency(samples=4):
    times = []
    for _ in range(samples):
        try:
            t0 = time.time()
            req = urllib.request.Request(DOWN_URL.format(0), headers=UA)
            urllib.request.urlopen(req, timeout=5).read()
            times.append((time.time() - t0) * 1000)
        except Exception:
            pass
    if not times:
        return None
    times.sort()
    return round(sum(times) / len(times), 1)


def _download(bytes_n=25_000_000, timeout=30):
    try:
        req = urllib.request.Request(DOWN_URL.format(bytes_n), headers=UA)
        t0 = time.time()
        total = 0
        with urllib.request.urlopen(req, timeout=timeout) as r:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
        dt = time.time() - t0
        if dt <= 0 or total == 0:
            return None
        return round((total * 8) / dt / 1_000_000, 1)  # Mbps
    except Exception:
        return None


def _upload(bytes_n=10_000_000, timeout=30):
    try:
        data = b"0" * bytes_n
        req = urllib.request.Request(UP_URL, data=data, headers=UA, method="POST")
        t0 = time.time()
        urllib.request.urlopen(req, timeout=timeout).read()
        dt = time.time() - t0
        if dt <= 0:
            return None
        return round((bytes_n * 8) / dt / 1_000_000, 1)
    except Exception:
        return None


def run_speedtest() -> dict:
    lat = _latency()
    down = _download()
    up = _upload()
    ok = any(v is not None for v in (lat, down, up))
    return {
        "ok": ok,
        "latency_ms": lat,
        "download_mbps": down,
        "upload_mbps": up,
        "server": "Cloudflare",
        "ts": time.time(),
        "error": None if ok else "No se pudo conectar a los servidores de medicion.",
    }


if __name__ == "__main__":
    print(run_speedtest())
