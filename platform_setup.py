"""
platform_setup.py — Deteccion del sistema y verificacion de requisitos.

Al arrancar, NetScope averigua en que SO corre (Windows / macOS / Linux),
si tiene permisos de admin/root y si estan las dependencias necesarias
(captura de paquetes, nmap, NetBIOS). Lo que se puede configurar solo, se
configura; lo que hay que instalar a mano, se explica con el comando exacto.
"""

import os
import sys
import platform
import shutil


# --------------------------------------------------------------------------- #
#  Identidad del sistema
# --------------------------------------------------------------------------- #
def detect_os() -> dict:
    s = platform.system()
    if s == "Darwin":
        ver = platform.mac_ver()[0] or ""
        return {"id": "macos", "name": f"macOS {ver}".strip()}
    if s == "Windows":
        return {"id": "windows", "name": f"Windows {platform.release()}"}
    if s == "Linux":
        name = "Linux"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        name = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
        return {"id": "linux", "name": name}
    return {"id": "unknown", "name": s or "desconocido"}


def is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """
    Relanza el proceso actual con privilegios de administrador/root.
    Devuelve True si YA se tienen privilegios (no hace nada).
    Devuelve False si lanzo una instancia elevada nueva y el proceso actual
    debe terminar.
    """
    if is_admin():
        return True
    system = platform.system()
    try:
        script = os.path.abspath(sys.argv[0])
        args = [script] + sys.argv[1:]
        if system == "Windows":
            import ctypes
            params = " ".join('"%s"' % a for a in args)
            workdir = os.path.dirname(script)
            # "runas" dispara el aviso de UAC
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, workdir, 1)
            return False  # el proceso actual (sin privilegios) debe salir
        else:
            # Re-ejecuta con sudo (pide contrasena). execvp reemplaza el proceso.
            os.execvp("sudo", ["sudo", sys.executable] + args)
            return False
    except Exception as e:
        print(f"No se pudo elevar privilegios automaticamente: {e}")
        return is_admin()


# --------------------------------------------------------------------------- #
#  Comprobaciones de dependencias
# --------------------------------------------------------------------------- #
def _check_scapy() -> bool:
    try:
        import scapy  # noqa: F401
        return True
    except Exception:
        return False


def _check_capture(os_id: str) -> dict:
    """Comprueba que exista el motor de captura (Npcap / libpcap)."""
    if not _check_scapy():
        return {"ok": False, "detail": "scapy no instalado",
                "hint": "pip install -r requirements.txt"}

    if os_id == "windows":
        windir = os.environ.get("WINDIR", r"C:\Windows")
        candidates = [
            os.path.join(windir, "System32", "Npcap"),
            os.path.join(windir, "System32", "wpcap.dll"),
            os.path.join(windir, "SysWOW64", "wpcap.dll"),
        ]
        if any(os.path.exists(c) for c in candidates):
            return {"ok": True, "detail": "Npcap detectado", "hint": ""}
        return {"ok": False, "detail": "Npcap no encontrado",
                "hint": "Instala Npcap desde https://npcap.com "
                        "(marca 'WinPcap API-compatible')."}

    # macOS / Linux usan libpcap, que scapy trae de la mano
    return {"ok": True, "detail": "libpcap disponible", "hint": ""}


def _check_nmap(os_id: str) -> dict:
    if shutil.which("nmap"):
        return {"ok": True, "detail": "nmap disponible", "hint": ""}
    hints = {
        "windows": "Instala nmap desde https://nmap.org/download",
        "macos": "brew install nmap",
        "linux": "sudo apt install nmap",
    }
    return {"ok": False, "detail": "nmap no encontrado",
            "hint": hints.get(os_id, "Instala nmap para el escaneo profundo.")}


def _check_netbios(os_id: str) -> dict:
    if os_id == "windows":
        # nbtstat viene con Windows
        return {"ok": bool(shutil.which("nbtstat")),
                "detail": "nbtstat (nativo)", "hint": ""}
    if shutil.which("nmblookup"):
        return {"ok": True, "detail": "nmblookup disponible", "hint": ""}
    hints = {
        "macos": "brew install samba  (opcional, mejora nombres de PCs Windows)",
        "linux": "sudo apt install samba-common-bin  (opcional)",
    }
    return {"ok": False, "detail": "nmblookup ausente (opcional)",
            "hint": hints.get(os_id, "")}


# --------------------------------------------------------------------------- #
#  Reporte completo
# --------------------------------------------------------------------------- #
_readiness_cache = {"data": None, "ts": 0.0}
_READINESS_TTL = 15.0   # segundos


def readiness(force: bool = False) -> dict:
    import time
    now = time.time()
    if (not force and _readiness_cache["data"] is not None
            and now - _readiness_cache["ts"] < _READINESS_TTL):
        return _readiness_cache["data"]
    os_info = detect_os()
    oid = os_info["id"]
    data = {
        "os": os_info,
        "python": platform.python_version(),
        "admin": is_admin(),
        "capture": _check_capture(oid),
        "nmap": _check_nmap(oid),
        "netbios": _check_netbios(oid),
    }
    _readiness_cache["data"] = data
    _readiness_cache["ts"] = now
    return data


def print_report(r: dict = None):
    r = r or readiness()
    def mark(ok): return "[OK]" if ok else "[--]"
    admin_word = "administrador/root" 
    print("-" * 60)
    print(f"  Sistema : {r['os']['name']}  (Python {r['python']})")
    print(f"  Permisos: {mark(r['admin'])} {admin_word}")
    print(f"  Captura : {mark(r['capture']['ok'])} {r['capture']['detail']}")
    print(f"  nmap    : {mark(r['nmap']['ok'])} {r['nmap']['detail']}")
    print(f"  NetBIOS : {mark(r['netbios']['ok'])} {r['netbios']['detail']}")
    if not r["admin"]:
        print()
        print("  AVISO: sin permisos de admin/root el escaneo y la captura no")
        if r["os"]["id"] == "windows":
            print("         funcionan. Cierra y abre PowerShell 'como Administrador'.")
        else:
            print("         funcionan. Ejecuta con:  sudo python3 app.py")
    for key in ("capture", "nmap", "netbios"):
        if not r[key]["ok"] and r[key]["hint"]:
            print(f"  -> {key}: {r[key]['hint']}")
    print("-" * 60)


if __name__ == "__main__":
    print_report()
