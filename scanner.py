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
import re
import time
from concurrent.futures import ThreadPoolExecutor

import psutil

_IS_WIN = platform.system() == "Windows"
_NO_WINDOW = 0x08000000 if _IS_WIN else 0

# --- caches (mac -> valor) -------------------------------------------------- #
_vendor_cache = {}
_name_cache = {}
_cache_lock = threading.Lock()
_metadata_cache = {}  # mac -> (ts, facts); evita repetir UPnP en cada autoescaneo
_metadata_lock = threading.Lock()

_mac_lookup = None
_mac_lock = threading.Lock()
_GENERIC_NAMES = {"", "(sin nombre)", "intel_ce_linux", "localhost",
                  "unknown", "desconocido"}


def usable_name(name: str) -> bool:
    value = (name or "").strip().lower()
    return value not in _GENERIC_NAMES and "intel_ce_linux" not in value


def seed_caches(site_id=None, clear=False):
    """Precarga fabricantes/nombres ya conocidos desde la BD (arranque instantaneo)."""
    try:
        from core import store
        data = store.seed_data(site_id)
        with _cache_lock:
            if clear:
                _vendor_cache.clear()
                _name_cache.clear()
            for mac, vendor in data["vendors"].items():
                _vendor_cache.setdefault(mac, vendor)
            for mac, name in data["names"].items():
                if usable_name(name):
                    _name_cache.setdefault(mac, name)
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


def _device_metadata(ip: str, mac: str) -> dict:
    now = time.time()
    key = (mac or "").lower()
    with _metadata_lock:
        cached = _metadata_cache.get(key)
        if cached:
            ttl = 6 * 3600 if cached[1] else 30 * 60
            if now - cached[0] < ttl:
                return dict(cached[1])
    facts = {}
    try:
        import fingerprint
        facts.update(fingerprint.probe_ssdp(ip, timeout=0.7))
    except Exception:
        pass
    model = mdns.model_for(ip) if "mdns" in globals() else ""
    if model:
        facts.setdefault("model_mdns", model)
    with _metadata_lock:
        if len(_metadata_cache) > 4096:
            oldest = min(_metadata_cache, key=lambda item: _metadata_cache[item][0])
            _metadata_cache.pop(oldest, None)
        _metadata_cache[key] = (now, dict(facts))
    return facts


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


def is_local_ip(ip: str) -> bool:
    """True si la IP cae dentro de alguna red local seleccionada para escanear.

    Sirve de guardarrail: intercepcion, bloqueo y escaneo profundo solo deben
    apuntar a equipos de la propia red, nunca a IPs externas arbitrarias.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    for _, cidr, _ in get_local_networks():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def get_gateway_ip() -> str:
    try:
        from scapy.all import conf
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return ""


# --- descubrimiento ARP (lo rapido) ---------------------------------------- #
def arp_scan(network: str, timeout: int = 2, iface: str = None):
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    options = {"timeout": timeout, "retry": 1, "verbose": 0}
    if iface:
        options["iface"] = iface
    answered, _ = srp(packet, **options)
    seen = {}
    for _, rcv in answered:
        seen[rcv.hwsrc] = rcv.psrc
    return [{"ip": ip, "mac": mac} for mac, ip in seen.items()]


_MAC_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")


def _normalise_mac(value: str) -> str:
    match = _MAC_PATTERN.search(value or "")
    if not match:
        return ""
    mac = match.group(0).replace("-", ":").lower()
    try:
        first = int(mac.split(":", 1)[0], 16)
    except ValueError:
        return ""
    if first & 1 or mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return ""
    return mac


def _parse_neighbor_output(text: str):
    """Extrae pares IPv4/MAC de arp/ip-neigh en Windows, Linux o macOS."""
    rows = []
    for line in (text or "").splitlines():
        mac = _normalise_mac(line)
        if not mac:
            continue
        ip_match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line)
        if not ip_match:
            continue
        try:
            ip = str(ipaddress.IPv4Address(ip_match.group(0)))
        except ipaddress.AddressValueError:
            continue
        rows.append({"ip": ip, "mac": mac, "discovery": "neighbor"})
    return rows


def _neighbor_cache():
    try:
        if _IS_WIN:
            command = ["arp", "-a"]
        elif platform.system() == "Linux":
            command = ["ip", "neigh", "show"]
        else:
            command = ["arp", "-an"]
        output = subprocess.run(command, capture_output=True, text=True, timeout=4,
                                creationflags=_NO_WINDOW).stdout
    except Exception:
        return []
    return _parse_neighbor_output(output)


def _network_for_ip(ip, networks):
    try:
        addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return None
    for iface, cidr, own_ip in networks:
        try:
            if addr in ipaddress.IPv4Network(cidr, strict=False):
                return iface, own_ip
        except ValueError:
            continue
    return None


def _own_devices(networks):
    """Incluye esta PC: una maquina no suele responder a su propio ARP broadcast."""
    mac_by_iface = {}
    for iface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == psutil.AF_LINK:
                mac = _normalise_mac(address.address)
                if mac:
                    mac_by_iface[iface] = mac
                    break
    return [{"ip": own_ip, "mac": mac_by_iface[iface], "iface": iface,
             "is_self": True, "discovery": "self"}
            for iface, _, own_ip in networks if iface in mac_by_iface]


def arp_only(timeout: int = 2, networks=None):
    """
    FASE 1: descubre IP+MAC de todas las redes locales (rapido) y pega el
    fabricante/nombre que ya este en cache. Devuelve la lista lista para mostrar.
    """
    found = {}
    networks = networks if networks is not None else get_local_networks()
    for iface, cidr, own_ip in networks:
        for dev in arp_scan(cidr, timeout=timeout, iface=iface):
            dev["iface"] = iface
            dev["discovery"] = "arp"
            found[dev["mac"].lower()] = dev
    # La tabla de vecinos conserva equipos vistos hace poco y sirve como
    # complemento si una respuesta ARP se perdio durante la rafaga del escaneo.
    used_ips = {dev["ip"] for dev in found.values()}
    for dev in _neighbor_cache():
        network = _network_for_ip(dev["ip"], networks)
        # Una entrada vieja puede conservar la MAC anterior de una IP. El ARP
        # activo es mas reciente y evita mostrar dos equipos con la misma IP.
        if not network or dev["ip"] in used_ips:
            continue
        dev["iface"] = network[0]
        if dev["mac"] not in found:
            found[dev["mac"]] = dev
            used_ips.add(dev["ip"])
    for dev in _own_devices(networks):
        for stale_mac, stale in list(found.items()):
            if stale.get("ip") == dev["ip"] and stale_mac != dev["mac"]:
                found.pop(stale_mac, None)
        found[dev["mac"]] = dev
    own_ips = {ip for _, _, ip in networks}

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
def _safe_close(zc):
    try:
        zc.close()
    except Exception:
        pass


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
        self.models = {}          # ip -> modelo publicado por mDNS (device-info)
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
            # modelo publicado en TXT (Apple usa 'model', otros 'md')
            model = ""
            try:
                props = info.properties or {}
                raw = props.get(b"model") or props.get(b"md")
                if raw:
                    model = raw.decode("utf-8", "ignore") if isinstance(raw, bytes) else str(raw)
            except Exception:
                model = ""
            for addr in info.parsed_addresses():
                if ":" not in addr:
                    self.map.setdefault(addr, pretty)
                    if model:
                        self.models.setdefault(addr, model)
        except Exception:
            pass

    def name_for(self, ip: str) -> str:
        return self.map.get(ip, "")

    def model_for(self, ip: str) -> str:
        return self.models.get(ip, "")

    def stop(self):
        """Cierra zeroconf en segundo plano (su close() puede bloquear en E/S;
        los hilos son daemon, asi que el proceso sale igual)."""
        zc, self._zc, self._browsers = self._zc, None, []
        if zc is not None:
            threading.Thread(target=lambda: _safe_close(zc), daemon=True).start()


mdns = MDNSResolver()


# --- FASE 2: enriquecimiento en paralelo ----------------------------------- #
def enrich(device: dict, own_ips=None) -> dict:
    own_ips = own_ips or set()
    ip, mac = device["ip"], device["mac"]
    key = mac.lower()

    # nombre: usa cache si ya hay uno "de verdad"; si no, resuelve.
    name = device.get("name", "") if usable_name(device.get("name")) else ""
    if not name:
        for resolver in (lambda: mdns.name_for(ip),
                         lambda: _netbios_name(ip),
                         lambda: _reverse_dns(ip)):
            candidate = resolver()
            if usable_name(candidate):
                name = candidate
                break
    device["name"] = name or "(sin nombre)"

    # fabricante: cache o lookup
    device["vendor"] = device.get("vendor") or _get_vendor(mac)
    device["is_self"] = ip in own_ips
    device["facts"] = _device_metadata(ip, mac)

    with _cache_lock:
        if usable_name(name):
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
