#!/usr/bin/env python3
"""
run.py — Instalador y lanzador de NetScope (todo en un paso).

Resuelve el problema de "en modo administrador no estan los paquetes":
crea un ENTORNO VIRTUAL (venv) y siempre usa el python del venv POR SU RUTA
COMPLETA. Como el venv se referencia por ruta (no por usuario), los paquetes
son visibles tanto para tu usuario como para el proceso elevado (admin/root).

Pasos:
  1. Crea el venv (venv/) si no existe.
  2. Instala las dependencias de Python DENTRO del venv.
  3. Instala nmap si falta (winget / brew / apt-dnf-pacman segun el SO).
  4. Lanza NetScope con el python del venv, elevando privilegios (UAC / sudo).

Uso:
    python run.py        # Windows
    python3 run.py       # macOS / Linux
"""

import os
import sys
import shutil
import platform
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(HERE, "venv")
IS_WIN = platform.system() == "Windows"


def osid() -> str:
    return {"Darwin": "macos", "Windows": "windows",
            "Linux": "linux"}.get(platform.system(), "unknown")


def venv_python() -> str:
    """Ruta ABSOLUTA al python del venv (funciona igual para usuario y admin)."""
    if IS_WIN:
        return os.path.join(VENV, "Scripts", "python.exe")
    return os.path.join(VENV, "bin", "python")


def run(cmd, **kw):
    print("   $", " ".join(str(c) for c in cmd))
    try:
        return subprocess.run(cmd, **kw)
    except FileNotFoundError:
        print("   ! comando no encontrado:", cmd[0])
        return None


# --------------------------------------------------------------------------- #
def ensure_venv():
    print("\n[1/4] Entorno virtual (venv)")
    if os.path.exists(venv_python()):
        print("   venv ya existe:", VENV)
        return True
    r = run([sys.executable, "-m", "venv", VENV])
    if r is None or r.returncode != 0 or not os.path.exists(venv_python()):
        print("   ! No se pudo crear el venv.")
        return False
    print("   venv creado en:", VENV)
    return True


def install_python_deps():
    print("\n[2/4] Dependencias de Python (dentro del venv)")
    req = os.path.join(HERE, "requirements.txt")
    if not os.path.exists(req):
        print("   ! no encontre requirements.txt")
        return False
    vp = venv_python()
    pip_check = run([vp, "-m", "pip", "--version"])
    if pip_check is None or pip_check.returncode != 0:
        print("   pip no esta disponible; intentando repararlo con ensurepip...")
        repaired = run([vp, "-m", "ensurepip", "--upgrade"])
        if repaired is None or repaired.returncode != 0:
            print("   ! No se pudo instalar pip dentro del venv.")
            return False
    upgraded = run([vp, "-m", "pip", "install", "--upgrade", "pip"])
    installed = run([vp, "-m", "pip", "install", "-r", req])
    if (upgraded is None or upgraded.returncode != 0
            or installed is None or installed.returncode != 0):
        print("   ! Fallo la instalacion de dependencias.")
        return False
    return True


def install_nmap(oid):
    print("\n[3/4] nmap")
    if shutil.which("nmap"):
        print("   nmap ya esta instalado.")
        return

    if oid == "windows":
        if shutil.which("winget"):
            run(["winget", "install", "--id", "Insecure.Nmap", "-e", "--silent",
                 "--accept-package-agreements", "--accept-source-agreements"])
        else:
            print("   ! winget no disponible. Instala nmap: https://nmap.org/download")

    elif oid == "macos":
        if shutil.which("brew"):
            run(["brew", "install", "nmap"])   # brew NO debe correr con sudo
        else:
            print("   ! Homebrew no instalado. Instalalo desde https://brew.sh")
            print("     o descarga nmap de https://nmap.org/download")

    elif oid == "linux":
        managers = [
            ("apt-get", ["apt-get", "install", "-y", "nmap"]),
            ("dnf",     ["dnf", "install", "-y", "nmap"]),
            ("pacman",  ["pacman", "-S", "--noconfirm", "nmap"]),
            ("zypper",  ["zypper", "install", "-y", "nmap"]),
        ]
        cmd = next((c for name, c in managers if shutil.which(name)), None)
        if cmd:
            if os.geteuid() != 0:
                cmd = ["sudo"] + cmd
            run(cmd)
        else:
            print("   ! no reconoci el gestor de paquetes; instala nmap a mano.")
    else:
        print("   ! sistema no reconocido; instala nmap a mano.")


def check_npcap(oid):
    if oid != "windows":
        return
    windir = os.environ.get("WINDIR", r"C:\Windows")
    paths = [os.path.join(windir, "System32", "Npcap"),
             os.path.join(windir, "System32", "wpcap.dll")]
    if not any(os.path.exists(p) for p in paths):
        print("\n   Aviso: no detecte Npcap (necesario para la captura).")
        print("   El instalador de nmap suele incluirlo. Si la captura falla,")
        print("   instala Npcap: https://npcap.com (marca 'WinPcap API-compatible').")


def launch_app_elevated(oid):
    print("\n[4/4] Iniciando NetScope con privilegios de administrador")
    vp = venv_python()
    app = os.path.join(HERE, "app.py")

    if oid == "windows":
        # Eleva el python DEL VENV (asi ve los paquetes instalados).
        import ctypes
        print("   Se abrira una ventana pidiendo permiso (UAC).")
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", vp, f'"{app}"', HERE, 1)
        if result <= 32:
            print(f"   ! No se pudo elevar NetScope (codigo {result}).")
            return False
    else:
        # sudo + python del venv (por ruta) => root ve los paquetes del venv.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            result = run([vp, app])
        else:
            print("   Te pedira la contrasena (sudo).")
            result = run(["sudo", vp, app])
        return bool(result and result.returncode == 0)
    return True


def main():
    oid = osid()
    print("=" * 60)
    print("  NetScope — instalador y lanzador")
    print("  Sistema:", platform.platform())
    print("=" * 60)
    if not ensure_venv():
        print("\nNo puedo continuar sin venv. Revisa tu instalacion de Python.")
        sys.exit(1)
    if not install_python_deps():
        print("\nNo puedo continuar sin las dependencias de Python.")
        sys.exit(1)
    install_nmap(oid)
    check_npcap(oid)
    if not launch_app_elevated(oid):
        sys.exit(1)


if __name__ == "__main__":
    main()
