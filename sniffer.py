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


class TrafficMonitor:
    MAX_EVENTS = 1000

    def __init__(self):
        self.stats = defaultdict(lambda: [0, 0, 0, 0, 0.0])  # pkts,bytes,sent,recv,last
        self.log = defaultdict(lambda: deque(maxlen=self.MAX_EVENTS))
        self._seq = 0
        self._lock = threading.Lock()
        self._thread = None
        self._running = False
        self._local_ips = set()
        self._inspected = set()   # solo estas IPs reciben analisis SNI/HTTP

    def set_local_ips(self, ips):
        self._local_ips = set(ips)

    def set_inspected(self, ips):
        self._inspected = set(ips)

    def _add_event(self, ip, kind, value):
        dq = self.log[ip]
        if dq and dq[-1]["value"] == value and dq[-1]["kind"] == kind:
            return
        self._seq += 1
        dq.append({"seq": self._seq, "ts": time.time(), "kind": kind, "value": value})

    def _handle(self, pkt):
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except Exception:
            return
        try:
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

            insp_src = src in self._inspected
            # DNS (barato, util siempre para IPs inspeccionadas o propias)
            udp = pkt.getlayer(UDP)
            if udp is not None and (udp.dport == 53 or udp.sport == 53):
                if insp_src or src in self._local_ips:
                    try:
                        from scapy.layers.dns import DNSQR
                        q = pkt.getlayer(DNSQR)
                        if q is not None and q.qname:
                            name = q.qname.decode(errors="ignore").rstrip(".")
                            if name and not name.endswith(".arpa"):
                                with self._lock:
                                    self._add_event(src, "dns", name)
                    except Exception:
                        pass
                return

            # SNI / HTTP SOLO para IPs interceptadas (evita el analisis masivo)
            if not insp_src:
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
            elif tcp.dport == 80:
                url = parse_http(load)
                if url:
                    with self._lock:
                        self._add_event(src, "http", url)
        except Exception:
            pass

    def _run(self):
        from scapy.all import sniff
        try:
            sniff(prn=self._handle, store=0,
                  stop_filter=lambda p: not self._running)
        except Exception:
            # fallback: reintento en bucle si sniff falla
            while self._running:
                try:
                    sniff(prn=self._handle, store=0, timeout=2)
                except Exception:
                    time.sleep(1)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def snapshot(self):
        with self._lock:
            data = [{
                "ip": ip, "packets": s[0], "bytes": s[1],
                "sent_bytes": s[2], "recv_bytes": s[3], "last_seen": s[4],
                "is_local": ip in self._local_ips,
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

    def summary(self):
        with self._lock:
            return {"traffic_ips": len(self.stats)}


monitor = TrafficMonitor()
