"""
wifi.py - Informacion de la red Wi-Fi (SSID, senal, canal, banda...) por SO.

Robusto, INDEPENDIENTE DEL IDIOMA y con PLAN B:
  - Windows: 'netsh wlan show interfaces' saca las etiquetas en el idioma del
    sistema (Senal/Canal en espanol, Signal/Channel en ingles...) y en la
    codificacion de consola (cp850/cp1252). Aqui se decodifica tolerante y las
    etiquetas se comparan por su "esqueleto" ASCII (sin tildes), asi funciona en
    cualquier idioma. Ademas se parsea POR INTERFAZ y se elige la que esta
    realmente CONECTADA (antes se aplanaba todo y con 2+ adaptadores Wi-Fi podia
    tomar el equivocado). Si netsh falla, se intenta PowerShell.
  - Si falta la banda, se deduce a partir del canal (2.4 / 5 / 6 GHz).
"""

import platform
import subprocess
import re
import unicodedata
import json
import time
from urllib.request import Request, urlopen

_IS_WIN = platform.system() == "Windows"

# En Windows, evita que parpadeen ventanas de consola al llamar netsh/powershell.
_NO_WINDOW = 0x08000000 if _IS_WIN else 0
_public_cache = {"data": None, "ts": 0.0}
_PUBLIC_TTL = 900


# --------------------------------------------------------------------------- #
#  Utilidades
# --------------------------------------------------------------------------- #
def _run(cmd, timeout=6):
    """Ejecuta un comando y devuelve su salida decodificada de forma tolerante."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=_NO_WINDOW)
    except Exception:
        return ""
    raw = p.stdout or b""
    for enc in ("utf-8", "cp1252", "cp850", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("latin-1", errors="ignore")


def _skeleton(s: str) -> str:
    """ASCII minusculas sin acentos. 'Senal'/'Se¤al' -> 'senal'."""
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if ord(c) < 128)
    return re.sub(r"\s+", " ", s).strip().lower()


def _band_from_channel(channel: str) -> str:
    m = re.search(r"\d+", channel or "")
    if not m:
        return ""
    ch = int(m.group())
    if 1 <= ch <= 14:
        return "2.4 GHz"
    if 32 <= ch <= 177:
        return "5 GHz"
    if ch >= 181:
        return "6 GHz"
    return ""


# --------------------------------------------------------------------------- #
#  Windows
# --------------------------------------------------------------------------- #
def _parse_win_block(block_lines):
    """Convierte un bloque de lineas 'Etiqueta : valor' en un dict de resultado."""
    pairs = []
    for line in block_lines:
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        pairs.append((_skeleton(label), value.strip()))

    def pick_exact(*keys):
        for want in keys:
            for lab, val in pairs:
                if lab == want and val:
                    return val
        return ""

    def pick_contains(*keys):
        for want in keys:
            for lab, val in pairs:
                if want in lab and val:
                    return val
        return ""

    ssid = pick_exact("ssid")
    if not ssid:
        return None

    channel = pick_contains("channel", "canal")
    band = pick_contains("band", "banda") or _band_from_channel(channel)

    return {
        "connected": True,
        "ssid": ssid,
        "bssid": pick_exact("bssid"),
        "signal": pick_contains("signal", "senal"),
        "channel": channel,
        "band": band,
        "radio": pick_contains("radio type", "tipo de radio", "radio"),
        "security": pick_contains("authentication", "autenticacion",
                                  "cifrado", "cipher"),
        "rx": pick_contains("receive rate", "recepcion"),
        "tx": pick_contains("transmit rate", "transmision"),
    }


def _windows():
    out = _run(["netsh", "wlan", "show", "interfaces"])
    if out:
        # netsh separa cada interfaz con una linea en blanco. Partimos en bloques
        # y elegimos el que esta CONECTADO; si ninguno lo indica, el que tenga SSID.
        blocks, current = [], []
        for line in out.splitlines():
            if line.strip() == "":
                if current:
                    blocks.append(current)
                    current = []
            else:
                current.append(line)
        if current:
            blocks.append(current)

        connected, any_ssid = None, None
        for b in blocks:
            parsed = _parse_win_block(b)
            if not parsed:
                continue
            any_ssid = any_ssid or parsed
            # estado conectado (multi-idioma): "connected" / "conectado"
            skel = " ".join(_skeleton(l) for l in b)
            if "connect" in skel or "conect" in skel:
                connected = parsed
                break
        result = connected or any_ssid
        if result:
            return result

    # Plan B: PowerShell (algunos equipos con netsh capado o WLAN raro).
    return _windows_powershell()


def _windows_powershell():
    ps = (
        "$p=Get-NetConnectionProfile | "
        "Where-Object {$_.InterfaceAlias -match 'Wi-Fi|Wireless|Inalambr'} | "
        "Select-Object -First 1; if($p){$p.Name}"
    )
    ssid = _run(["powershell", "-NoProfile", "-Command", ps]).strip()
    if ssid:
        return {
            "connected": True,
            "ssid": ssid,
            "details_note": "Windows requiere permisos de administrador y ubicación activa para mostrar todos los detalles Wi-Fi.",
        }
    return {"connected": False}


# --------------------------------------------------------------------------- #
#  macOS
# --------------------------------------------------------------------------- #
def _macos():
    ssid = ""
    for dev in ("en0", "en1"):
        m = re.search(r"Current Wi-Fi Network:\s*(.+)",
                      _run(["networksetup", "-getairportnetwork", dev]))
        if m:
            ssid = m.group(1).strip()
            break

    sp = _run(["system_profiler", "SPAirPortDataType"], timeout=8)
    if not ssid:
        m = re.search(r"Current Network Information:\s*\n\s*(.+?):", sp)
        if m:
            ssid = m.group(1).strip()
    if not ssid:
        return {"connected": False}

    info = {"connected": True, "ssid": ssid}
    for key, label in [("signal", "Signal / Noise"), ("channel", "Channel"),
                       ("radio", "PHY Mode"), ("security", "Security")]:
        m = re.search(rf"{label}:\s*(.+)", sp)
        if m:
            info[key] = m.group(1).strip()
    info["band"] = _band_from_channel(info.get("channel", ""))
    return info


# --------------------------------------------------------------------------- #
#  Linux
# --------------------------------------------------------------------------- #
def _split_terse(line):
    return re.split(r"(?<!\\):", line)


def _linux():
    out = _run(["nmcli", "-t", "-f", "active,ssid,signal,chan,rate,security",
                "dev", "wifi"])
    for line in out.splitlines():
        parts = [p.replace("\\:", ":") for p in _split_terse(line)]
        if parts and parts[0] == "yes":
            channel = parts[3] if len(parts) > 3 else ""
            return {
                "connected": True,
                "ssid": parts[1] if len(parts) > 1 else "",
                "signal": (parts[2] + "%") if len(parts) > 2 and parts[2] else "",
                "channel": channel,
                "band": _band_from_channel(channel),
                "rx": parts[4] if len(parts) > 4 else "",
                "security": parts[5] if len(parts) > 5 else "",
            }
    ssid = _run(["iwgetid", "-r"]).strip()
    return {"connected": True, "ssid": ssid} if ssid else {"connected": False}


# --------------------------------------------------------------------------- #
def get_wifi_info() -> dict:
    try:
        s = platform.system()
        if s == "Windows":
            info = _windows()
        elif s == "Darwin":
            info = _macos()
        elif s == "Linux":
            info = _linux()
        else:
            info = {"connected": False}
        info["internet"] = get_public_network_info()
        return info
    except Exception:
        pass
    return {"connected": False}


def get_public_network_info() -> dict:
    """Obtiene datos aproximados de la IP pública sin bloquear la interfaz."""
    now = time.time()
    if _public_cache["data"] is not None and now - _public_cache["ts"] < _PUBLIC_TTL:
        return _public_cache["data"]
    try:
        request = Request("https://ipapi.co/json/", headers={"User-Agent": "NetScope/1.0"})
        with urlopen(request, timeout=3) as response:
            raw = json.load(response)
        data = {
            "ip": raw.get("ip", ""),
            "provider": raw.get("org", "") or raw.get("asn", ""),
            "asn": raw.get("asn", ""),
            "city": raw.get("city", ""),
            "region": raw.get("region", ""),
            "country": raw.get("country_name", ""),
            "timezone": raw.get("timezone", ""),
        }
    except Exception:
        data = {"error": "información de Internet no disponible"}
    _public_cache["data"] = data
    _public_cache["ts"] = now
    return data


# --------------------------------------------------------------------------- #
#  Escaner de redes Wi-Fi al alcance (wardriving basico)
#
#  Muestra TODAS las redes que la tarjeta ve, con BSSID, banda, canal, senal,
#  seguridad, etc. Limites honestos en Windows (netsh): NO expone WPS, beacon
#  interval ni TSF (eso necesita modo monitor 802.11, no soportado). El
#  "last seen" lo llevamos nosotros entre escaneos.
# --------------------------------------------------------------------------- #
_ap_seen = {}   # bssid -> {first_seen, last_seen}


def _chan_to_freq(channel, band=""):
    """Frecuencia central aproximada (MHz) a partir del canal (y banda si se sabe)."""
    m = re.search(r"\d+", str(channel or ""))
    if not m:
        return None
    ch = int(m.group())
    b = band or ""
    if "6" in b:
        return 5950 + ch * 5
    if "2.4" in b or (not b and 1 <= ch <= 14):
        return 2484 if ch == 14 else 2407 + ch * 5
    if "5" in b or (not b and 32 <= ch <= 177):
        return 5000 + ch * 5
    return None


def _run_raw(cmd, timeout=15):
    """Como _run pero junta stdout+stderr (netsh escupe avisos por ambos)."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=_NO_WINDOW)
    except Exception:
        return ""
    raw = (p.stdout or b"") + b"\n" + (p.stderr or b"")
    for enc in ("utf-8", "cp1252", "cp850", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("latin-1", errors="ignore")


def _parse_networks_windows(text):
    """Parte la salida de 'netsh wlan show networks mode=bssid' en una fila por
    BSSID. Independiente del idioma (compara por 'esqueleto' ASCII)."""
    rows = []
    ssid = auth = enc = ntype = ""
    cur = None
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        label, value = raw.split(":", 1)
        skel = _skeleton(label)
        value = value.strip()
        if skel.startswith("bssid "):           # ¡antes que 'ssid'! bssid contiene ssid
            cur = {"ssid": ssid, "bssid": value.lower(), "security": auth,
                   "encryption": enc, "net_type": ntype, "signal": "",
                   "radio": "", "band": "", "channel": ""}
            rows.append(cur)
        elif skel.startswith("ssid "):
            ssid, auth, enc, ntype, cur = value, "", "", "", None
        elif cur is None:                        # propiedades a nivel de SSID
            if "autenticacion" in skel or "authentication" in skel:
                auth = value
            elif "cifrado" in skel or "encryption" in skel:
                enc = value
            elif "tipo de red" in skel or "network type" in skel:
                ntype = value
        else:                                    # propiedades a nivel de BSSID
            if "senal" in skel or "signal" in skel:
                cur["signal"] = value
            elif "tipo de radio" in skel or "radio type" in skel:
                cur["radio"] = value
            elif skel == "banda" or skel == "band":
                cur["band"] = value
            elif "canal" in skel or "channel" in skel:
                cur["channel"] = value
    return rows


def _finalize_ap(n):
    """Deriva banda/frecuencia/seguridad y actualiza first/last seen."""
    band = n.get("band") or _band_from_channel(n.get("channel", ""))
    n["band"] = band
    n["freq_mhz"] = _chan_to_freq(n.get("channel", ""), band)
    sec = _skeleton(n.get("security", ""))
    n["open"] = (not sec) or any(k in sec for k in ("abierta", "open", "ninguna", "none"))
    n["wps"] = None                              # netsh no lo expone
    m = re.search(r"\d+", n.get("signal", "") or "")
    n["signal_pct"] = int(m.group()) if m else None
    key = n.get("bssid", "")
    now = time.time()
    seen = _ap_seen.get(key)
    if seen:
        seen["last_seen"] = now
    else:
        _ap_seen[key] = {"first_seen": now, "last_seen": now}
    n["first_seen"] = _ap_seen[key]["first_seen"]
    n["last_seen"] = _ap_seen[key]["last_seen"]
    return n


def scan_networks() -> dict:
    """Escanea las redes Wi-Fi al alcance. Devuelve
    {ok, networks:[...], count, ts} o {ok:False, error, detail}."""
    system = platform.system()
    if system == "Windows":
        text = _run_raw(["netsh", "wlan", "show", "networks", "mode=bssid"])
        skel = _skeleton(text)
        if "ssid" not in skel and ("ubicacion" in skel or "location" in skel):
            return {"ok": False, "error": "location",
                    "detail": "Windows exige los Servicios de ubicación ACTIVADOS "
                              "para listar redes Wi-Fi (además de admin, que NetScope "
                              "ya tiene). Actívalos en Configuración > Privacidad y "
                              "seguridad > Ubicación. Si ahí ves 'Algunas opciones las "
                              "administra tu organización', tu empresa los bloquea por "
                              "política y no se puede escanear en este equipo: no es un "
                              "fallo de NetScope, es un control de Windows/IT."}
        rows = _parse_networks_windows(text)
        if not rows and "interfaz" not in skel and "interface" not in skel:
            return {"ok": False, "error": "no_wifi",
                    "detail": "No se detectó un adaptador Wi-Fi o no hay redes visibles."}
    elif system == "Linux":
        text = _run_raw(["nmcli", "-t", "-f",
                         "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,RATE", "dev", "wifi"])
        rows = _parse_networks_nmcli(text)
    else:
        return {"ok": False, "error": "unsupported",
                "detail": "El escaneo de redes al alcance solo está disponible "
                          "en Windows y Linux por ahora."}
    nets = [_finalize_ap(n) for n in rows]
    # Fabricante del router por su MAC (OUI), reutilizando la base y cache que ya
    # mantiene el scanner (no descarga nada extra).
    try:
        import scanner
        for n in nets:
            v = scanner._get_vendor(n["bssid"])
            n["vendor"] = "" if (not v or v.lower() == "desconocido") else v
    except Exception:
        for n in nets:
            n.setdefault("vendor", "")
    # Marca cual es la red a la que ESTAS conectado ahora.
    current = _connected_bssid()
    for n in nets:
        n["is_current"] = bool(current) and n["bssid"] == current
    nets.sort(key=lambda x: (not x.get("is_current"),
                             x["signal_pct"] is None, -(x["signal_pct"] or 0)))
    return {"ok": True, "networks": nets, "count": len(nets), "ts": time.time()}


def _connected_bssid() -> str:
    """MAC (BSSID) del punto de acceso al que estamos conectados ahora, o ''."""
    system = platform.system()
    try:
        if system == "Windows":
            text = _run(["netsh", "wlan", "show", "interfaces"])
            for raw in text.splitlines():
                if ":" not in raw:
                    continue
                label, value = raw.split(":", 1)
                if _skeleton(label) == "bssid":
                    return value.strip().lower()
        elif system == "Linux":
            text = _run(["nmcli", "-t", "-f", "active,bssid", "dev", "wifi"])
            for line in text.splitlines():
                parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
                if parts and parts[0] == "yes" and len(parts) > 1:
                    return parts[1].lower()
    except Exception:
        pass
    return ""


def _parse_networks_nmcli(text):
    rows = []
    for line in text.splitlines():
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 6 or not parts[1]:
            continue
        rows.append({"ssid": parts[0], "bssid": parts[1].lower(),
                     "channel": parts[2], "band": "", "signal": parts[4] + "%",
                     "security": parts[5], "encryption": "", "net_type": "",
                     "radio": parts[6] if len(parts) > 6 else ""})
    return rows


if __name__ == "__main__":
    print(json.dumps(get_wifi_info(), indent=2, ensure_ascii=False))
    print(json.dumps(scan_networks(), indent=2, ensure_ascii=False, default=str))
