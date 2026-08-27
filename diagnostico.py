"""
diagnostico.py — Revisa por que NetScope no lee la red / WiFi / router.

Ponlo en la carpeta del proyecto (junto a app.py) y ejecutalo:

    python diagnostico.py

Si algo falla necesita permisos, cierra y vuelve a abrir la terminal
"como administrador" y repitelo. El script NO cambia nada: solo mira y reporta.
"""

import os
import sys
import platform
import shutil
import subprocess

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; RST = "\033[0m"
try:
    os.system("")   # habilita colores ANSI en la consola de Windows
except Exception:
    pass

def ok(t):   print(f"  {G}[OK]{RST} {t}")
def bad(t):  print(f"  {R}[XX]{RST} {t}")
def warn(t): print(f"  {Y}[--]{RST} {t}")
def head(t): print(f"\n{'='*58}\n  {t}\n{'='*58}")

problemas = []

# --------------------------------------------------------------------------- #
head("1. Sistema y permisos")
print(f"  SO      : {platform.platform()}")
print(f"  Python  : {platform.python_version()}  ({sys.executable})")

is_admin = False
try:
    import ctypes
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
except Exception:
    try:
        is_admin = os.geteuid() == 0
    except Exception:
        pass
if is_admin:
    ok("Ejecutandose como ADMINISTRADOR")
else:
    bad("NO eres administrador  <-- el escaneo y la captura NO funcionan sin esto")
    problemas.append(
        "Abre PowerShell 'como administrador' (clic derecho) y corre de nuevo,\n"
        "     o mejor usa:  python run.py  (eleva permisos solo).")

# --------------------------------------------------------------------------- #
head("2. Dependencias de Python (donde CORRE este python)")
# Ojo: si corres como admin en otra consola, puede ser OTRO python sin paquetes.
for mod in ("scapy", "flask", "psutil", "zeroconf", "mac_vendor_lookup"):
    try:
        __import__(mod)
        ok(f"{mod}")
    except Exception as e:
        bad(f"{mod}  no importa ({e})")
        problemas.append(f"Falta '{mod}'. Instala:  {sys.executable} -m pip "
                         f"install -r requirements.txt")

# --------------------------------------------------------------------------- #
head("3. Motor de captura (Npcap en Windows / libpcap en Linux-Mac)")
oid = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
    platform.system(), "?")
if oid == "windows":
    windir = os.environ.get("WINDIR", r"C:\Windows")
    cands = [os.path.join(windir, "System32", "Npcap"),
             os.path.join(windir, "System32", "wpcap.dll"),
             os.path.join(windir, "SysWOW64", "wpcap.dll")]
    if any(os.path.exists(c) for c in cands):
        ok("Npcap detectado")
    else:
        bad("Npcap NO encontrado  <-- sin esto no hay escaneo ni captura")
        problemas.append(
            "Instala Npcap desde https://npcap.com  (MARCA la casilla\n"
            "     'Install Npcap in WinPcap API-compatible Mode').")
else:
    ok("libpcap (lo trae scapy en Linux/macOS)")

# --------------------------------------------------------------------------- #
head("4. nmap (solo para el escaneo profundo, opcional)")
if shutil.which("nmap"):
    ok("nmap disponible")
else:
    warn("nmap ausente (el resumen y el escaneo ARP NO lo necesitan)")

# --------------------------------------------------------------------------- #
head("5. Interfaces de red e IPs locales (necesita psutil)")
try:
    import socket, psutil
    encontrada = False
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                print(f"     {iface}: {a.address} / {a.netmask}")
                encontrada = True
    if encontrada:
        ok("Hay al menos una IP local valida")
    else:
        bad("No se ve ninguna IP local  <-- no estas conectado a la red?")
        problemas.append("Conectate al WiFi/cable y repite el diagnostico.")
except Exception as e:
    bad(f"No pude leer interfaces: {e}")

# --------------------------------------------------------------------------- #
head("6. Router / gateway (lo que sale vacio en 'Resumen')")
try:
    from scapy.all import conf
    gw = conf.route.route("0.0.0.0")[2]
    if gw and gw != "0.0.0.0":
        ok(f"Gateway detectado: {gw}")
    else:
        bad("scapy no ve el gateway")
        problemas.append("Suele ser Npcap ausente o falta de permisos (ver arriba).")
except Exception as e:
    bad(f"scapy no pudo calcular la ruta: {e}")
    problemas.append("Reinstala scapy y Npcap; ejecuta como administrador.")

# --------------------------------------------------------------------------- #
head("7. Escaneo ARP real (la prueba de fuego)")
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    from scanner import get_local_networks
    selected = get_local_networks()
    target_iface = selected[0][0] if selected else None
    target_net = selected[0][1] if selected else None
    if not target_net:
        warn("No hay una red donde escanear (sin IP local)")
    else:
        print(f"     Escaneando {target_net} por {target_iface} (5 s)...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_net),
                 iface=target_iface, timeout=5, retry=1, verbose=0)
        n = len(ans)
        if n > 0:
            ok(f"ARP funciona: {n} dispositivo(s) respondieron")
        else:
            bad("ARP no obtuvo respuestas  <-- captura bloqueada o aislamiento WiFi")
            problemas.append(
                "0 respuestas suele ser: (a) sin admin, (b) Npcap ausente, o\n"
                "     (c) el router tiene 'aislamiento de clientes' activo en el WiFi.")
except PermissionError:
    bad("Permiso denegado en la captura  <-- ejecuta como administrador")
    problemas.append("Falta de permisos: abre la consola como administrador.")
except Exception as e:
    bad(f"El escaneo ARP fallo: {e}")
    problemas.append(f"Error de captura: {e}. Revisa Npcap y permisos.")

# --------------------------------------------------------------------------- #
head("8. WiFi (usa netsh en Windows, no scapy)")
if oid == "windows":
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                             capture_output=True, timeout=6).stdout
        txt = out.decode("latin-1", errors="ignore")
        if "SSID" in txt or "ssid" in txt.lower():
            ok("netsh responde y hay una interfaz WiFi")
            for line in txt.splitlines():
                low = line.lower()
                if ("ssid" in low and "bssid" not in low) or "senal" in low or "signal" in low:
                    print("     ", line.strip())
        else:
            bad("netsh no reporta WiFi  <-- no hay adaptador WiFi o esta apagado")
            problemas.append(
                "Si tu PC es de escritorio con cable, es normal no tener WiFi.\n"
                "     Si tienes WiFi, activalo y conectate a una red.")
    except Exception as e:
        bad(f"netsh fallo: {e}")
else:
    warn("Comprobacion de WiFi por consola solo implementada para Windows aqui")

# --------------------------------------------------------------------------- #
head("RESUMEN")
if not problemas:
    print(f"  {G}Todo en orden.{RST} Si aun asi la web falla, reinicia app.py.")
else:
    print(f"  Se encontraron {len(problemas)} cosa(s) a resolver:\n")
    for i, p in enumerate(problemas, 1):
        print(f"  {i}. {p}\n")
    print("  Arregla de arriba hacia abajo: casi siempre es admin + Npcap.")
print()
