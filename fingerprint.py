"""
fingerprint.py — Saca MAS datos de un dispositivo sin instalar nada en el:
modelo comercial, fabricante real, version del sistema, tipo de equipo.

Combina tres fuentes, de mas a menos rica segun el tipo de equipo:

  1. User-Agent HTTP  (parse_user_agent): capturado por el sniffer al INSPECCIONAR.
     Es lo mas jugoso para MOVILES y PCs: revela modelo exacto ("2201117TG" =
     Redmi Note 11) y version de Android/iOS/Windows. Solo aparece en trafico
     HTTP sin cifrar, cada vez mas raro, pero muchas apps/updates aun lo usan.

  2. UPnP / SSDP  (probe_ssdp): pregunta al equipo por su descripcion UPnP.
     Es la mejor fuente para TVs, routers, impresoras, consolas, altavoces y
     mucho IoT: devuelve fabricante, modelName, modelNumber y nombre amistoso.

  3. (fuera de aqui) OUI del fabricante y nmap -O, que ya recoge el resto de la app.

Nota honesta de alcance: un movil moderno NO publica su nombre comercial por la
red salvo que lo pilles por User-Agent (fuente 1). Sin trafico HTTP suyo, lo
maximo fiable es "Xiaomi · Android 13" (OUI + nmap), no "Redmi Note 11" exacto.
"""

import re
import socket
from urllib.request import urlopen


# --------------------------------------------------------------------------- #
#  1) User-Agent HTTP  ->  modelo / sistema
# --------------------------------------------------------------------------- #
# Modelos Apple: el User-Agent solo dice "iPhone"; el modelo real (iPhone15,2)
# aparece por otras vias. Aqui mapeamos lo que si es legible.
def parse_user_agent(ua: str) -> dict:
    """Devuelve {'os':..., 'model':..., 'app':...} a partir de un User-Agent.

    Best-effort: rellena solo lo que reconoce. Nunca lanza."""
    ua = (ua or "").strip()
    if not ua:
        return {}
    out = {}

    # ---- Android: "(Linux; Android 13; 2201117TG Build/TP1A...)" ----
    m = re.search(r"Android\s+([\d.]+)", ua)
    if m:
        out["os"] = "Android " + m.group(1)
        # el modelo va entre la version y "Build/"
        mm = re.search(r"Android[^;]*;\s*([^;)]+?)\s+Build/", ua)
        if not mm:
            # algunos UA no traen Build/: "...; 2201117TG)"
            mm = re.search(r"Android[\d. ]*;\s*([^;)]+?)\)", ua)
        if mm:
            model = mm.group(1).strip()
            # recorta sufijos de capa/version del fabricante ("Redmi Note 8 Pro
            # MIUI/V12.5" -> "Redmi Note 8 Pro")
            model = re.split(r"\s+(?:MIUI|EMUI|HarmonyOS|HMSCore|ColorOS|Build)/",
                             model)[0].strip()
            # descarta placeholders genericos de WebView / apps
            if model and model.lower() not in ("wv", "k", "; wv", "generic"):
                out["model"] = model
        return out

    # ---- iOS / iPadOS ----
    m = re.search(r"iPhone OS (\d+[_\d]*)", ua)
    if m:
        out["os"] = "iOS " + m.group(1).replace("_", ".")
        out["model"] = "iPhone"
        return out
    m = re.search(r"iPad;\s*CPU OS (\d+[_\d]*)", ua)
    if m:
        out["os"] = "iPadOS " + m.group(1).replace("_", ".")
        out["model"] = "iPad"
        return out

    # ---- Windows ----
    if "Windows NT 10.0" in ua:
        out["os"] = "Windows 10/11"
        return out
    m = re.search(r"Windows NT ([\d.]+)", ua)
    if m:
        out["os"] = "Windows NT " + m.group(1)
        return out

    # ---- macOS ----
    m = re.search(r"Mac OS X (\d+[_\d]*)", ua)
    if m:
        out["os"] = "macOS " + m.group(1).replace("_", ".")
        return out

    # ---- Otros ----
    if "CrOS" in ua:
        out["os"] = "ChromeOS"
    elif "Linux" in ua:
        out["os"] = "Linux"
    return out


# --------------------------------------------------------------------------- #
#  2) UPnP / SSDP  ->  fabricante / modelo / nombre amistoso
# --------------------------------------------------------------------------- #
def probe_ssdp(ip: str, timeout: float = 2.0) -> dict:
    """Pregunta por UPnP al equipo (M-SEARCH unicast). Si responde, baja su
    descripcion XML y saca datos. Devuelve {} si el equipo no habla UPnP."""
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           "HOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\n'
           "MX: 1\r\n"
           "ST: ssdp:all\r\n\r\n").encode()
    server, location = "", ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(msg, (ip, 1900))
        for _ in range(5):                     # varias respuestas posibles
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            if addr[0] != ip:
                continue
            text = data.decode("latin-1", "ignore")
            for line in text.split("\r\n"):
                low = line.lower()
                if low.startswith("server:") and not server:
                    server = line.split(":", 1)[1].strip()
                elif low.startswith("location:") and not location:
                    location = line.split(":", 1)[1].strip()
            if location:
                break
    except Exception:
        return {}
    finally:
        try:
            sock.close()
        except Exception:
            pass

    info = {}
    if server:
        info["server"] = server
    if location:
        info.update(_fetch_upnp_desc(location))
    return info


def _fetch_upnp_desc(url: str, timeout: float = 2.0) -> dict:
    """Descarga la descripcion UPnP (device.xml) y extrae los campos utiles."""
    try:
        with urlopen(url, timeout=timeout) as r:
            xml = r.read(65536).decode("utf-8", "ignore")
    except Exception:
        return {}

    def tag(name):
        m = re.search(r"<%s>(.*?)</%s>" % (name, name), xml, re.I | re.S)
        return m.group(1).strip() if m else ""

    out = {}
    for key, tagname in (("manufacturer", "manufacturer"),
                         ("model_name", "modelName"),
                         ("model_number", "modelNumber"),
                         ("model_desc", "modelDescription"),
                         ("friendly_name", "friendlyName"),
                         ("device_type", "deviceType")):
        v = tag(tagname)
        if v:
            # deviceType viene como urn:schemas-upnp-org:device:MediaRenderer:1
            if key == "device_type" and ":" in v:
                v = v.rstrip(":1234567890").split(":")[-1] or v
            out[key] = v
    return out


# --------------------------------------------------------------------------- #
#  Resumen legible a partir de todos los datos (facts) que tengamos
# --------------------------------------------------------------------------- #
def best_model(facts: dict) -> str:
    """Elige la mejor etiqueta de MODELO disponible entre todas las fuentes."""
    facts = facts or {}
    for key in ("model_name", "model_ua", "friendly_name", "model_number"):
        if facts.get(key):
            return facts[key]
    return ""


def best_os(facts: dict) -> str:
    facts = facts or {}
    return facts.get("os_ua") or facts.get("os_nmap") or ""
