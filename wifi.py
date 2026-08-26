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

_IS_WIN = platform.system() == "Windows"

# En Windows, evita que parpadeen ventanas de consola al llamar netsh/powershell.
_NO_WINDOW = 0x08000000 if _IS_WIN else 0


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
        return {"connected": True, "ssid": ssid}
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
            return _windows()
        if s == "Darwin":
            return _macos()
        if s == "Linux":
            return _linux()
    except Exception:
        pass
    return {"connected": False}


if __name__ == "__main__":
    import json
    print(json.dumps(get_wifi_info(), indent=2, ensure_ascii=False))
