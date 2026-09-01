"""
sniffer.py - Captura de trafico + log de conexiones (DNS / SNI / HTTP).

Optimizaciones para que no se trabe:
  - Captura CONTINUA (una sola llamada a sniff), no reiniciando cada 2s.
  - El manejo por paquete hace lo minimo (contadores) y evita f-strings.
  - El analisis pesado (SNI/HTTP) SOLO se hace para las IPs que estas
    interceptando, no para todo el trafico -> muchisimo menos trabajo.
"""

import time
import threading
import ipaddress
from collections import defaultdict, deque


def parse_sni(payload: bytes):
    try:
        if len(payload) < 43 or payload[0] != 0x16:
            return None
        idx = 5
        if payload[idx] != 0x01:
            return None
        idx += 4 + 2 + 32
        sid_len = payload[idx]; idx += 1 + sid_len
        if idx + 2 > len(payload): return None
        cs_len = int.from_bytes(payload[idx:idx+2], "big"); idx += 2 + cs_len
        if idx + 1 > len(payload): return None
        comp_len = payload[idx]; idx += 1 + comp_len
        if idx + 2 > len(payload): return None
        ext_total = int.from_bytes(payload[idx:idx+2], "big"); idx += 2
        end = min(len(payload), idx + ext_total)
        while idx + 4 <= end:
            etype = int.from_bytes(payload[idx:idx+2], "big"); idx += 2
            elen = int.from_bytes(payload[idx:idx+2], "big"); idx += 2
            if etype == 0x00:
                if idx + 5 > len(payload): return None
                nlen = int.from_bytes(payload[idx+3:idx+5], "big")
                return payload[idx+5:idx+5+nlen].decode(errors="ignore") or None
            idx += elen
        return None
    except Exception:
        return None


def parse_http(payload: bytes):
    try:
        text = payload[:2048].decode("latin-1", errors="ignore")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) >= 3 and parts[0] in ("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH") and parts[2].startswith("HTTP/"):
            host = ""
            for ln in lines[1:]:
                if ln.lower().startswith("host:"):
                    host = ln.split(":", 1)[1].strip(); break
            return ("http://" + host + parts[1]) if host else parts[1]
    except Exception:
        pass
    return None


def parse_http_ua(payload: bytes):
    """Saca la cabecera User-Agent de una peticion HTTP (revela modelo/SO)."""
    try:
        text = payload[:4096].decode("latin-1", errors="ignore")
        for ln in text.split("\r\n"):
            if ln.lower().startswith("user-agent:"):
                ua = ln.split(":", 1)[1].strip()
                return ua or None
    except Exception:
        pass
    return None


class TrafficMonitor:
    MAX_EVENTS = 1000
    MAX_STATS = 10000

    def __init__(self):
        self.stats = defaultdict(lambda: [0, 0, 0, 0, 0.0])  # pkts,bytes,sent,recv,last
        self.log = defaultdict(lambda: deque(maxlen=self.MAX_EVENTS))
        self._seq = 0
        self._lock = threading.Lock()
        self._thread = None
        self._running = False
        self._local_ips = set()
        self._local_networks = ()
        self._inspected = set()   # solo estas IPs reciben analisis SNI/HTTP
        self._dhcp = {}           # mac -> huella DHCP (opcion 55 [+ 60])
        self._dhcp_host = {}      # mac -> hostname anunciado por DHCP (opcion 12)
        self._ip6_ll_by_mac = {}  # mac -> link-local IPv6 (fe80::) para cortar IPv6
        self._ext_names = {}      # ip externa -> dominio (de respuestas DNS / SNI)
        self._ptr_tried = set()   # ips a las que ya se les intento DNS inverso
        self._http_ua = {}        # ip local -> mejor User-Agent visto (modelo/SO)

    def set_local_context(self, ips, networks=()):
        """Actualiza IPs propias y subredes observadas de forma atomica."""
        parsed = []
        for cidr in networks:
            try:
                parsed.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        with self._lock:
            self._local_ips = set(ips)
            self._local_networks = tuple(parsed)

    def set_local_ips(self, ips):
        """Compatibilidad con llamadas antiguas."""
        self.set_local_context(ips)

    def set_inspected(self, ips):
        with self._lock:
            self._inspected = set(ips)

    def _is_local(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in network for network in self._local_networks)

    def dhcp_fp_for(self, mac):
        """Huella DHCP observada para una MAC (vacio si aun no se vio ningun DHCP)."""
        return self._dhcp.get((mac or "").lower(), "")

    def dhcp_host_for(self, mac):
        """Hostname que el equipo anuncio por DHCP (vacio si no se ha visto)."""
        return self._dhcp_host.get((mac or "").lower(), "")

    def ip6_ll_for(self, mac):
        """Link-local IPv6 vista para una MAC (vacio si aun no se ha observado)."""
        return self._ip6_ll_by_mac.get((mac or "").lower(), "")

    def device_ua(self, ip):
        """Mejor User-Agent HTTP visto para una IP local (vacio si ninguno)."""
        return self._http_ua.get(ip, "")

    _MAX_EXT_NAMES = 8000

    def _note_ext(self, ip, name):
        if ip and name and (ip in self._ext_names
                            or len(self._ext_names) < self._MAX_EXT_NAMES):
            self._ext_names.setdefault(ip, name)

    def note_name(self, ip, name):
        if not ip:
            return
        self._ptr_tried.add(ip)
        self._note_ext(ip, name)

    def ptr_tried(self, ip):
        return ip in self._ptr_tried

    def _add_event(self, ip, kind, value):
        dq = self.log[ip]
        if dq and dq[-1]["value"] == value and dq[-1]["kind"] == kind:
            return
        self._seq += 1
        dq.append({"seq": self._seq, "ts": time.time(), "kind": kind, "value": value})

    def _prune_stats_locked(self):
        """Acota peers historicos sin expulsar equipos locales o inspeccionados."""
        if len(self.stats) <= self.MAX_STATS:
            return
        removable = [
            (values[4], ip) for ip, values in self.stats.items()
            if ip not in self._inspected and not self._is_local(ip)
        ]
        target_size = max(1, int(self.MAX_STATS * 0.8))
        for _, ip in sorted(removable)[:max(1, len(self.stats) - target_size)]:
            self.stats.pop(ip, None)
            self._ext_names.pop(ip, None)
            self._ptr_tried.discard(ip)
            self.log.pop(ip, None)

    def _handle(self, pkt):
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except Exception:
            return
        try:
            # IPv6: aprende la link-local (fe80::) de cada equipo por su MAC.
            # Hace falta para poder CORTAR el IPv6 (bloqueo por NDP). Los equipos
            # anuncian su link-local por NDP multicast, asi que lo vemos sin MITM.
            try:
                from scapy.layers.inet6 import IPv6
                ip6 = pkt.getlayer(IPv6)
                if ip6 is not None and (ip6.src or "").startswith("fe80"):
                    self._ip6_ll_by_mac[(pkt.src or "").lower()] = ip6.src
            except Exception:
                pass

            ip_layer = pkt.getlayer(IP)
            if ip_layer is None:
                return
            src = ip_layer.src
            dst = ip_layer.dst
            size = len(pkt)

            # contadores (barato)
            with self._lock:
                s = self.stats[src]; s[0]+=1; s[1]+=size; s[2]+=size; s[4]=time.time()
                d = self.stats[dst]; d[0]+=1; d[1]+=size; d[3]+=size; d[4]=s[4]
                self._prune_stats_locked()

            insp_src = src in self._inspected
            udp = pkt.getlayer(UDP)

            # DHCP (puertos 67/68): huella de opciones -> re-vincula un equipo
            # cuando SOLO cambio la MAC. Barato: los DHCP son poco frecuentes.
            if udp is not None and (udp.dport == 67 or udp.dport == 68
                                    or udp.sport == 67 or udp.sport == 68):
                self._handle_dhcp(pkt)
                return

            # DNS (barato, util siempre para IPs inspeccionadas o propias)
            if udp is not None and (udp.dport == 53 or udp.sport == 53):
                try:
                    from scapy.layers.dns import DNSQR, DNSRR
                    if (insp_src or src in self._local_ips):
                        q = pkt.getlayer(DNSQR)
                        if q is not None and q.qname:
                            name = q.qname.decode(errors="ignore").rstrip(".")
                            if name and not name.endswith(".arpa"):
                                with self._lock:
                                    self._add_event(src, "dns", name)
                    # respuestas: mapea IP externa -> dominio (para nombrar peers)
                    ans = pkt.getlayer(DNSRR)
                    while ans is not None:
                        if getattr(ans, "type", None) in (1, 28) and ans.rdata:  # A / AAAA
                            rr = ans.rrname.decode(errors="ignore").rstrip(".") if ans.rrname else ""
                            addr = ans.rdata if isinstance(ans.rdata, str) else str(ans.rdata)
                            self._note_ext(addr, rr)
                        ans = ans.payload.getlayer(DNSRR) if ans.payload else None
                except Exception:
                    pass
                return

            # De aqui en adelante, SOLO para IPs interceptadas (evita el
            # analisis masivo de todo el trafico de la red).
            if not insp_src:
                return

            # QUIC / HTTP3 (UDP 443): hoy MUCHO trafico (YouTube, Google, Meta,
            # WhatsApp...) va por aqui, no por TCP. El contenido va cifrado, pero
            # registramos A DONDE habla: el dominio si lo conocemos (por DNS/SNI),
            # o la IP. Solo miramos los paquetes de "cabecera larga" (arranque de
            # conexion) para no meter una linea por cada paquete de datos.
            if udp is not None:
                if udp.dport == 443:
                    load = bytes(udp.payload)
                    if load and (load[0] & 0xC0) == 0xC0:
                        with self._lock:
                            self._add_event(src, "quic", self._ext_names.get(dst) or dst)
                return

            tcp = pkt.getlayer(TCP)
            if tcp is None:
                return
            load = bytes(tcp.payload)
            if not load:
                return
            if tcp.dport == 443 and load[:1] == b"\x16":
                sni = parse_sni(load)
                if sni:
                    with self._lock:
                        self._add_event(src, "sni", sni)
                    self._note_ext(dst, sni)
                else:
                    # ClientHello partido en varios segmentos o con ECH: no hay
                    # SNI legible, pero si conocemos el destino lo mostramos igual.
                    known = self._ext_names.get(dst)
                    if known:
                        with self._lock:
                            self._add_event(src, "sni", known)
            elif tcp.dport == 80:
                url = parse_http(load)
                if url:
                    with self._lock:
                        self._add_event(src, "http", url)
                ua = parse_http_ua(load)
                if ua:
                    # nos quedamos con el UA mas largo (suele ser el mas completo)
                    if len(ua) > len(self._http_ua.get(src, "")):
                        self._http_ua[src] = ua
                    with self._lock:
                        self._add_event(src, "ua", ua)
        except Exception:
            pass

    def _handle_dhcp(self, pkt):
        try:
            from scapy.layers.dhcp import DHCP, BOOTP
        except Exception:
            return
        try:
            dhcp = pkt.getlayer(DHCP)
            bootp = pkt.getlayer(BOOTP)
            if dhcp is None or bootp is None or not dhcp.options:
                return
            opts = {}
            for o in dhcp.options:
                if not isinstance(o, (tuple, list)) or len(o) < 2:
                    continue
                # scapy da la opcion como ('clave', valor) o ('clave', v1, v2, ...)
                opts[o[0]] = list(o[1:]) if len(o) > 2 else o[1]

            raw = bytes(bootp.chaddr)[:6]
            mac = ":".join("%02x" % b for b in raw)
            if not mac or mac == "00:00:00:00:00:00":
                return
            mac = mac.lower()

            # Hostname (opcion 12): el NOMBRE que el propio equipo anuncia al pedir
            # IP. Es la mejor fuente de nombres en una LAN domestica (mDNS/NetBIOS/
            # DNS-inverso casi nunca resuelven moviles o IoT). Ej: "Redmi-Note-11".
            host = opts.get("hostname")
            if host:
                if isinstance(host, bytes):
                    host = host.decode(errors="ignore")
                host = str(host).strip()
                if host:
                    self._dhcp_host[mac] = host

            # Huella DHCP (opcion 55 [+ 60]): re-vincula un equipo cuando cambia
            # solo la MAC. Puede faltar en un ACK del servidor: no pasa nada.
            prl = opts.get("param_req_list")
            if prl:
                if not isinstance(prl, (list, tuple)):
                    prl = [prl]
                fp = ",".join(str(x) for x in prl)
                vcls = opts.get("vendor_class_id")
                if vcls:
                    if isinstance(vcls, bytes):
                        vcls = vcls.decode(errors="ignore")
                    fp += "|" + str(vcls)
                self._dhcp[mac] = fp
        except Exception:
            pass

    def _run(self):
        from scapy.all import sniff
        # Un timeout corto permite que stop() termine incluso en una red sin
        # paquetes; stop_filter solo se evalua cuando llega uno.
        while self._running:
            try:
                sniff(prn=self._handle, store=0, timeout=2)
            except Exception:
                time.sleep(1)

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self):
        self._running = False
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=3)
        self._thread = None

    def snapshot(self):
        with self._lock:
            data = [{
                "ip": ip, "packets": s[0], "bytes": s[1],
                "sent_bytes": s[2], "recv_bytes": s[3], "last_seen": s[4],
                "is_local": self._is_local(ip),
                "host": "" if self._is_local(ip) else self._ext_names.get(ip, ""),
            } for ip, s in self.stats.items()]
        data.sort(key=lambda x: x["bytes"], reverse=True)
        return data

    def log_since(self, ip, since_seq=0, limit=300):
        with self._lock:
            items = [e for e in self.log.get(ip, ()) if e["seq"] > since_seq]
        return items[-limit:]

    def reset_log(self, ip):
        with self._lock:
            self.log.pop(ip, None)

    def reset(self):
        with self._lock:
            self.stats.clear()
            self.log.clear()
            self._http_ua.clear()

    def summary(self):
        with self._lock:
            return {"traffic_ips": len(self.stats)}


monitor = TrafficMonitor()
