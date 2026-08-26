"""
scanner.py - Descubrimiento de dispositivos (ARP) + resolucion de nombres.

DISENADO PARA QUE SE SIENTA INSTANTANEO:
  - Fase 1 (arp_only): descubre IP+MAC de toda la red por ARP. Es lo rapido.
    A cada equipo se le pega YA su fabricante y nombre si estan en cache, asi la
    lista aparece de inmediato sin esperar a nada.
  - Fase 2 (enrich_all): resuelve nombres (mDNS -> DNS inverso -> NetBIOS) y
    fabricantes que falten, EN PARALELO y con timeouts cortos. Se llama en
    segundo plano; la interfaz se va rellenando sola.

Ademas:
  - La base de fabricantes (mac-vendor-lookup) se descarga UNA vez al arrancar
    (prewarm) en segundo plano, para que NUNCA cuelgue un escaneo.
  - Nombres y fabricantes se cachean en memoria (y se siembran desde la BD), asi
    los re-escaneos son practicamente instantaneos.
"""

import socket
import subprocess
import platform
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor

import psutil

_IS_WIN = platform.system() == "Windows"
_NO_WINDOW = 0x08000000 if _IS_WIN else 0

# --- caches (mac -> valor) -------------------------------------------------- #
_vendor_cache = {}
_name_cache = {}
_cache_lock = threading.Lock()

_mac_lookup = None
_mac_lock = threading.Lock()


def seed_caches_from_storage():
    """Precarga fabricantes/nombres ya conocidos desde la BD (arranque instantaneo)."""
    try:
        import storage
        for d in storage.all_devices():
            mac = (d.get("mac") or "").lower()
            if not mac:
                continue
            if d.get("vendor"):
                _vendor_cache.setdefault(mac, d["vendor"])
            if d.get("auto_name"):
                _name_cache.setdefault(mac, d["auto_name"])
    except Exception:
        pass


# --- fabricante (OUI) ------------------------------------------------------- #
def _ensure_mac_lookup():
    global _mac_lookup
    if _mac_lookup is not None:
        return _mac_lookup
    with _mac_lock:
        if _mac_lookup is None:
            try:
                from mac_vendor_lookup import MacLookup
                _mac_lookup = MacLookup()
            except Exception:
                _mac_lookup = False  # marca "no disponible" para no reintentar en bucle
    return _mac_lookup


def prewarm_vendors():
    """Descarga/actualiza la base OUI una sola vez, sin bloquear los escaneos."""
    ml = _ensure_mac_lookup()
    if not ml:
        return
    try:
        ml.update_vendors()   # descarga la lista si hace falta (una vez)
    except Exception:
        pass


def _get_vendor(mac: str) -> str:
    key = (mac or "").lower()
    with _cache_lock:
        if key in _vendor_cache:
            return _vendor_cache[key]
    ml = _ensure_mac_lookup()
    vendor = "Desconocido"
    if ml:
        try:
            vendor = ml.lookup(mac)
        except Exception:
            vendor = "Desconocido"
    with _cache_lock:
        _vendor_cache[key] = vendor
    return vendor


# --- topologia local -------------------------------------------------------- #
# Interfaces que NO son la red fisica real (WSL, VPNs, virtualizacion, etc.).
# Se descartan por nombre como red de seguridad; el filtro principal es el
# gateway (ver _select_networks).
_VIRTUAL_HINTS = ("loopback", "vethernet", "wsl", "vmware", "virtualbox",
                  "vbox", "tailscale", "tap-windows", "openvpn", "tun",
                  "wintun", "bluetooth", "hyper-v", "docker")


def _is_link_local(ip: str) -> bool:
    # 169.254.x.x = APIPA: la interfaz NO consiguio IP por DHCP -> sin red real.
    return ip.startswith("169.254.")


def _looks_virtual(iface_name: str) -> bool:
    n = iface_name.lower()
    return any(h in n for h in _VIRTUAL_HINTS)


def _select_networks(candidates, gateway):
    """
    Elige QUE redes escanear de entre todas las interfaces del equipo.

    El problema que resuelve: una PC con WSL, VPN, Tailscale, Bluetooth, etc.
    tiene muchas interfaces IPv4. Escanearlas todas hace que el escaneo se vaya
    a una red virtual VACIA (p.ej. la de WSL) y devuelva cero dispositivos.

    Estrategia, en orden:
      1) Quedarse con la red que CONTIENE el gateway (la que tiene internet).
      2) Si no se sabe el gateway, descartar interfaces virtuales por nombre.
      3) Ultimo recurso: lo que haya.
    """
    parsed = []
    for c in candidates:
        iface, ip, mask = c["iface"], c["ip"], c["netmask"]
        if not mask or ip.startswith("127.") or _is_link_local(ip):
            continue
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        if net.num_addresses > 4096:
            continue
        parsed.append((iface, net, ip))

    if gateway:
        try:
            gw = ipaddress.IPv4Address(gateway)
            primary = [(i, str(n), ip) for (i, n, ip) in parsed if gw in n]
            if primary:
                return primary
        except ValueError:
            pass

    real = [(i, str(n), ip) for (i, n, ip) in parsed if not _looks_virtual(i)]
    if real:
        return real

    return [(i, str(n), ip) for (i, n, ip) in parsed]


def get_local_networks():
    gw = get_gateway_ip()
    candidates = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                candidates.append({"iface": iface, "ip": addr.address,
                                   "netmask": addr.netmask})
    return _select_networks(candidates, gw)


def get_gateway_ip() -> str:
    try:
        from scapy.all import conf
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return ""


# --- descubrimiento ARP (lo rapido) ---------------------------------------- #
def arp_scan(network: str, timeout: int = 2):
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(packet, timeout=timeout, retry=1, verbose=0)
    seen = {}
    for _, rcv in answered:
        seen[rcv.hwsrc] = rcv.psrc
    return [{"ip": ip, "mac": mac} for mac, ip in seen.items()]


def arp_only(timeout: int = 2):
    """
    FASE 1: descubre IP+MAC de todas las redes locales (rapido) y pega el
    fabricante/nombre que ya este en cache. Devuelve la lista lista para mostrar.
    """
    found = {}
    for iface, cidr, own_ip in get_local_networks():
        for dev in arp_scan(cidr, timeout=timeout):
            dev["iface"] = iface
            found[dev["mac"]] = dev
    own_ips = {ip for _, _, ip in get_local_networks()}

    devices = []
    with _cache_lock:
        for dev in found.values():
            key = dev["mac"].lower()
            dev["vendor"] = _vendor_cache.get(key, "")
            dev["name"] = _name_cache.get(key, "")
            dev["is_self"] = dev["ip"] in own_ips
            devices.append(dev)
    return devices


# --- resolucion de nombres (timeouts cortos) ------------------------------- #
def _reverse_dns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.8)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def _netbios_name(ip: str) -> str:
    try:
        if _IS_WIN:
            out = subprocess.run(["nbtstat", "-A", ip], capture_output=True,
                                 text=True, timeout=1.2,
                                 creationflags=_NO_WINDOW).stdout
            for line in out.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    return line.split()[0].strip()
        else:
            out = subprocess.run(["nmblookup", "-A", ip], capture_output=True,
                                 text=True, timeout=1.2).stdout
            for line in out.splitlines():
                if "<00>" in line and "GROUP" not in line:
                    return line.split()[0].strip()
    except Exception:
        pass
    return ""


# --- mDNS / Bonjour (nombres bonitos, desde cache instantaneo) ------------- #
class MDNSResolver:
    SERVICES = [
        "_workstation._tcp.local.", "_device-info._tcp.local.",
        "_airplay._tcp.local.", "_raop._tcp.local.",
        "_googlecast._tcp.local.", "_smb._tcp.local.",
        "_afpovertcp._tcp.local.", "_ipp._tcp.local.",
        "_printer._tcp.local.", "_http._tcp.local.",
        "_ssh._tcp.local.", "_homekit._tcp.local.",
    ]

    def __init__(self):
        self.map = {}
        self._zc = None
        self._browsers = []

    def start(self):
        try:
            from zeroconf import Zeroconf, ServiceBrowser
        except Exception:
            return
        try:
            self._zc = Zeroconf()
            for svc in self.SERVICES:
                self._browsers.append(
                    ServiceBrowser(self._zc, svc, handlers=[self._on_change]))
        except Exception:
            self._zc = None

    def _on_change(self, zeroconf, service_type, name, state_change):
        try:
            info = zeroconf.get_service_info(service_type, name, timeout=1200)
            if not info:
                return
            pretty = name.split("." + service_type.split(".", 1)[0])[0]
            for addr in info.parsed_addresses():
                if ":" not in addr:
                    self.map.setdefault(addr, pretty)
        except Exception:
            pass

    def name_for(self, ip: str) -> str:
        return self.map.get(ip, "")


mdns = MDNSResolver()


# --- FASE 2: enriquecimiento en paralelo ----------------------------------- #
def enrich(device: dict, own_ips=None) -> dict:
    own_ips = own_ips or set()
    ip, mac = device["ip"], device["mac"]
    key = mac.lower()

    # nombre: usa cache si ya hay uno "de verdad"; si no, resuelve.
    name = device.get("name", "")
    if not name or name == "(sin nombre)":
        name = mdns.name_for(ip) or _reverse_dns(ip) or _netbios_name(ip)
    device["name"] = name or "(sin nombre)"

    # fabricante: cache o lookup
    device["vendor"] = device.get("vendor") or _get_vendor(mac)
    device["is_self"] = ip in own_ips

    with _cache_lock:
        if name:
            _name_cache[key] = name
        if device["vendor"]:
            _vendor_cache[key] = device["vendor"]
    return device


def enrich_all(devices, own_ips=None):
    """Enriquece EN SITIO (muta los mismos dicts) para que la vista los vea al vuelo."""
    if not devices:
        return devices
    own_ips = own_ips or set()
    workers = min(32, max(4, len(devices)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda d: enrich(d, own_ips=own_ips), devices))
    return devices


# --- compatibilidad: escaneo completo en una sola llamada ------------------ #
def scan_all(timeout: int = 2):
    own_ips = {ip for _, _, ip in get_local_networks()}
    devices = arp_only(timeout=timeout)
    enrich_all(devices, own_ips=own_ips)
    return devices
