"""
app.py - Servidor de NetScope (multi-pagina + API).

Sirve con waitress (servidor WSGI de produccion, mucho mas fluido que el server
de desarrollo de Flask) si esta disponible; si no, cae al de Flask.
"""

import signal
import sys
import threading
import time
import platform
import subprocess
from urllib.request import urlopen

from flask import Flask, jsonify, render_template, request

import scanner
import deepscan
import platform_setup
import wifi
import notify
from core import store, identity
from sniffer import monitor
from mitm import interceptor, blocker

app = Flask(__name__)

# Sitio (casa / empresa) que administra esta instalacion. Se fija en _startup().
SITE = None

# Solo se sirve en 127.0.0.1. Rechazamos Host ajenos para cerrar el vector de
# DNS-rebinding: sin esto, una web cualquiera podria conducir esta API local
# (que hace ARP spoofing y bloqueos) desde el navegador del usuario.
_ALLOWED_HOSTS = {"127.0.0.1:5000", "localhost:5000", "127.0.0.1", "localhost"}


@app.before_request
def _guard_host():
    host = (request.host or "").lower()
    if host not in _ALLOWED_HOSTS:
        return ("host no permitido", 403)

_last_scan = {"devices": [], "gateway": "", "ts": 0, "enriching": False,
              "error": "", "by_identity": {}, "known_ids": set()}
_scan_lock = threading.Lock()
_enrich_lock = threading.Lock()
_summary_cache = {"data": None, "ts": 0.0}
_SUMMARY_TTL = 3.0
_health_cache = {"data": None, "ts": 0.0}
_HEALTH_TTL = 10.0
_traffic_state = {"ts": 0.0, "sent": 0, "recv": 0, "peak": 0.0}
_AUTO_SCAN_SECS = 15   # re-escaneo automatico en segundo plano


def _do_scan_fast():
    """FASE 1: ARP rapido. Publica los equipos al instante (con datos de cache)."""
    with _scan_lock:
        networks = scanner.get_local_networks()
        if not networks:
            raise RuntimeError("no se detecto ninguna red local para escanear")
        own_ips = {ip for _, _, ip in networks}
        devices = scanner.arp_only(networks=networks)
        gateway = scanner.get_gateway_ip()
        _last_scan["devices"] = devices
        _last_scan["gateway"] = gateway
        _last_scan["ts"] = time.time()
        _last_scan["error"] = ""
        monitor.set_local_ips(list(own_ips))
    return devices, own_ips


def _enrich_and_store(devices, own_ips):
    """FASE 2: resuelve nombres/fabricantes, funde cada equipo en su IDENTIDAD
    (ver core/identity.py) y guarda la observacion. Muta los dicts ya publicados."""
    with _enrich_lock:
        _last_scan["enriching"] = True
        try:
            prev_known = set(_last_scan.get("known_ids") or ())
            first_run = not prev_known
            scanner.enrich_all(devices, own_ips=own_ips)
            by_identity = {}
            for d in devices:
                dhcp_fp = monitor.dhcp_fp_for(d["mac"])
                obs = {"mac": d["mac"], "ip": d["ip"],
                       "hostname": d.get("name", ""),
                       "vendor": d.get("vendor", ""), "dhcp_fp": dhcp_fp}
                iid = identity.resolve(SITE, obs)
                d["identity_id"] = iid
                vendor = d.get("vendor", "")
                if vendor and vendor.lower() != "desconocido":
                    store.set_identity_vendor(iid, vendor)
                store.record_observation(SITE, "arp", identity_id=iid, mac=d["mac"],
                                         ip=d["ip"], hostname=d.get("name", ""),
                                         vendor=d.get("vendor", ""), dhcp_fp=dhcp_fp)
                by_identity[iid] = d
                ident = store.get_identity(iid) or {}
                d["custom_name"] = ident.get("label_manual") or ""
                if iid not in prev_known and not first_run:
                    label = (ident.get("label_manual") or ident.get("label")
                             or d.get("vendor") or "equipo")
                    store.record_event(SITE, iid, "nuevo",
                                       detail=f"{label} · {d['ip']}", severity="warn")
                    try:
                        notify.notify_new_device(label, d["ip"], d.get("vendor", ""))
                    except Exception:
                        pass
            _last_scan["by_identity"] = by_identity
            _last_scan["known_ids"] = {i["id"] for i in store.all_identities(SITE)}
            _last_scan["ts"] = time.time()
        except Exception as e:
            _last_scan["error"] = str(e)
        finally:
            _last_scan["enriching"] = False


def _do_scan():
    """Escaneo completo (sincrono). Se usa al arrancar y en el bucle automatico."""
    devices, own_ips = _do_scan_fast()
    _enrich_and_store(devices, own_ips)
    return devices


def _auto_scan_loop():
    """Mantiene la lista fresca sola, sin que el usuario tenga que pulsar nada."""
    while True:
        time.sleep(_AUTO_SCAN_SECS)
        try:
            _do_scan()
        except Exception as e:
            _last_scan["error"] = str(e)


def _background_scan():
    try:
        _do_scan()
    except Exception as e:
        _last_scan["error"] = str(e)


def _online_device_for(identity_id):
    return _last_scan.get("by_identity", {}).get(identity_id)


def _identity_for_ip(ip):
    for iid, d in _last_scan.get("by_identity", {}).items():
        if d.get("ip") == ip:
            return iid
    return None


def _target_ip_from_payload(payload):
    """Resuelve la IP objetivo de una accion (inspect/block) desde el body.

    Acepta identity_id (preferido) o ip directa. Devuelve None si el equipo
    esta ausente o la IP no es local."""
    iid = payload.get("identity_id")
    if iid is not None:
        d = _online_device_for(int(iid))
        ip = d["ip"] if d else None
    else:
        ip = payload.get("ip") or None
    if ip and not scanner.is_local_ip(ip):
        return None
    return ip


def _identity_view(ident, online, traffic_by_ip, last_obs=None):
    """Combina una identidad persistida con su presencia y trafico actuales."""
    online = online or {}
    last_obs = last_obs or {}
    ip = online.get("ip") or last_obs.get("ip") or ""
    stats = traffic_by_ip.get(online.get("ip"), {}) if online.get("ip") else {}
    label = ident.get("label_manual") or ident.get("label") or ""
    return {
        "identity_id": ident["id"],
        "label": ident.get("label") or "",
        "label_manual": ident.get("label_manual") or "",
        "name": label or "(sin nombre)",
        "custom_name": ident.get("label_manual") or "",
        "confidence": round(ident.get("confidence") or 0.0, 2),
        "trusted": bool(ident.get("trusted")),
        "first_seen": ident.get("first_seen"),
        "last_seen": ident.get("last_seen"),
        "online": bool(online),
        "ip": ip,
        "mac": online.get("mac") or last_obs.get("mac") or "",
        "vendor": online.get("vendor") or ident.get("vendor") or last_obs.get("vendor") or "",
        "iface": online.get("iface", ""),
        "is_self": bool(online.get("is_self")),
        "traffic": stats.get("bytes", 0),
        "sent_bytes": stats.get("sent_bytes", 0),
        "recv_bytes": stats.get("recv_bytes", 0),
    }


def _sync_inspected():
    monitor.set_inspected(set(interceptor.list_targets()))


def _network_health():
    now = time.time()
    if _health_cache["data"] is not None and now - _health_cache["ts"] < _HEALTH_TTL:
        return _health_cache["data"]
    gateway = _last_scan["gateway"] or scanner.get_gateway_ip()
    result = {"gateway": gateway, "latency_ms": None, "packet_loss": None,
              "internet": False}
    if gateway:
        command = (["ping", "-n", "1", "-w", "800", gateway]
                   if platform.system() == "Windows"
                   else ["ping", "-c", "1", "-W", "1", gateway])
        started = time.perf_counter()
        try:
            process = subprocess.run(command, capture_output=True, timeout=2)
            if process.returncode == 0:
                result["latency_ms"] = round((time.perf_counter() - started) * 1000)
                result["packet_loss"] = 0
            else:
                result["packet_loss"] = 100
        except Exception:
            result["packet_loss"] = 100
    try:
        with urlopen("https://www.google.com/generate_204", timeout=2):
            result["internet"] = True
    except Exception:
        pass
    _health_cache["data"] = result
    _health_cache["ts"] = now
    return result


# ==== Paginas ============================================================== #
@app.route("/")
def page_overview():
    return render_template("overview.html", seccion="resumen")

@app.route("/devices")
def page_devices():
    return render_template("devices.html", seccion="devices")

@app.route("/traffic")
def page_traffic():
    return render_template("traffic.html", seccion="traffic")

@app.route("/speed")
def page_speed():
    return render_template("speed.html", seccion="speed")

@app.route("/device/<int:identity_id>")
def page_device(identity_id):
    return render_template("device.html", seccion="devices", identity_id=identity_id)

@app.route("/history")
def page_history():
    return render_template("history.html", seccion="history")

@app.route("/settings")
def page_settings():
    return render_template("settings.html", seccion="settings")

@app.route("/system")
def page_system():
    return render_template("system.html", seccion="system")


# ==== API ================================================================== #
@app.route("/api/summary")
def api_summary():
    now = time.time()
    if _summary_cache["data"] and now - _summary_cache["ts"] < _SUMMARY_TTL:
        return jsonify(_summary_cache["data"])
    r = platform_setup.readiness()
    traffic = monitor.snapshot()
    local_ips = {d["ip"] for d in _last_scan["devices"]}
    local_traffic = [t for t in traffic if t["ip"] in local_ips]
    traffic_totals = {
        "bytes": sum(t["bytes"] for t in local_traffic),
        "sent_bytes": sum(t["sent_bytes"] for t in local_traffic),
        "recv_bytes": sum(t["recv_bytes"] for t in local_traffic),
    }
    previous_ts = _traffic_state["ts"]
    if previous_ts:
        elapsed = max(now - previous_ts, 0.001)
        sent_rate = max(0, traffic_totals["sent_bytes"] - _traffic_state["sent"]) / elapsed
        recv_rate = max(0, traffic_totals["recv_bytes"] - _traffic_state["recv"]) / elapsed
        current_rate = sent_rate + recv_rate
        _traffic_state["peak"] = max(_traffic_state["peak"], current_rate)
    else:
        sent_rate = recv_rate = 0.0
    _traffic_state.update({"ts": now, "sent": traffic_totals["sent_bytes"],
                           "recv": traffic_totals["recv_bytes"]})
    idents = store.all_identities(SITE)
    labels = {i["id"]: (i.get("label_manual") or i.get("label") or "") for i in idents}
    events = store.list_events(SITE, 5)
    for e in events:
        e["label"] = labels.get(e.get("identity_id"), "")
    day_ago = time.time() - 86400
    new_today = sum(1 for e in store.list_events(SITE, 500)
                    if e.get("type") == "nuevo" and (e.get("ts") or 0) >= day_ago)
    data = {
        "devices": len(_last_scan["devices"]),
        "inspecting": interceptor.list_targets(),
        "traffic_ips": len(local_traffic),
        "gateway": _last_scan["gateway"],
        "os": r["os"], "admin": r["admin"], "nmap": r["nmap"]["ok"],
        "health": _network_health(),
        "traffic": {
            **traffic_totals, "sent_rate": sent_rate, "recv_rate": recv_rate,
            "peak_rate": _traffic_state["peak"],
        },
        "devices_info": {
            "unknown": sum(1 for i in idents if not i.get("trusted")),
            "new_today": new_today,
            "named": sum(1 for i in idents if (i.get("label_manual") or i.get("label"))),
        },
        "security": {
            "admin": r["admin"], "capture": r["capture"]["ok"],
            "nmap": r["nmap"]["ok"], "netbios": r["netbios"]["ok"],
        },
        "events": events,
    }
    _summary_cache["data"] = data
    _summary_cache["ts"] = now
    return jsonify(data)


@app.route("/api/system")
def api_system():
    return jsonify(platform_setup.readiness())

@app.route("/api/wifi")
def api_wifi():
    return jsonify(wifi.get_wifi_info())

@app.route("/api/networks")
def api_networks():
    nets = [{"iface": i, "cidr": c, "ip": ip} for i, c, ip in scanner.get_local_networks()]
    return jsonify({"networks": nets, "nmap": deepscan.nmap_available()})

@app.route("/api/devices")
def api_devices():
    traffic_by_ip = {t["ip"]: t for t in monitor.snapshot()}
    by_identity = _last_scan.get("by_identity", {})
    rows = [_identity_view(i, by_identity.get(i["id"]), traffic_by_ip)
            for i in store.all_identities(SITE)]
    seen_ips = {r["ip"] for r in rows if r["ip"]}
    # equipos vistos en el escaneo rapido pero aun sin identidad resuelta
    for d in _last_scan["devices"]:
        if d.get("identity_id") or d.get("ip") in seen_ips:
            continue
        stats = traffic_by_ip.get(d.get("ip"), {})
        rows.append({
            "identity_id": None, "label": "", "label_manual": "",
            "name": d.get("name") or "(sin nombre)", "custom_name": "",
            "confidence": 0.0, "trusted": False, "online": True,
            "ip": d.get("ip", ""), "mac": d.get("mac", ""),
            "vendor": d.get("vendor", ""), "iface": d.get("iface", ""),
            "is_self": bool(d.get("is_self")),
            "first_seen": None, "last_seen": None,
            "traffic": stats.get("bytes", 0),
            "sent_bytes": stats.get("sent_bytes", 0),
            "recv_bytes": stats.get("recv_bytes", 0),
        })
    return jsonify({"devices": rows, "gateway": _last_scan["gateway"],
                    "ts": _last_scan["ts"],
                    "enriching": _last_scan.get("enriching", False),
                    "error": _last_scan.get("error", "")})

@app.route("/api/device/<int:identity_id>")
def api_device(identity_id):
    ident = store.get_identity(identity_id)
    if not ident or ident.get("site_id") != SITE:
        return jsonify({"ok": False, "error": "identidad no encontrada"}), 404
    traffic_by_ip = {t["ip"]: t for t in monitor.snapshot()}
    online = _online_device_for(identity_id)
    last_obs = store.last_observation(identity_id)
    view = _identity_view(ident, online, traffic_by_ip, last_obs=last_obs)
    signals = store.signals_of(identity_id)
    history = [e for e in store.list_events(SITE, 500)
              if e.get("identity_id") == identity_id]
    return jsonify({"ok": True, "device": view, "signals": signals,
                    "ports": store.ports_of(identity_id), "history": history,
                    "inspecting": bool(view["ip"]) and view["ip"] in interceptor.list_targets()})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        devices, own_ips = _do_scan_fast()
        # nombres/identidades se resuelven en segundo plano (la vista se rellena sola)
        threading.Thread(target=_enrich_and_store, args=(devices, own_ips),
                         daemon=True).start()
        return jsonify({"ok": True, "count": len(devices), "devices": devices,
                        "gateway": _last_scan["gateway"], "enriching": True})
    except Exception as e:
        _last_scan["error"] = str(e)
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/traffic")
def api_traffic():
    by_ip = {d["ip"]: d for d in _last_scan["devices"]}
    id_by_ip = {d.get("ip"): iid for iid, d in _last_scan.get("by_identity", {}).items()}
    rows, externals = [], []
    for t in monitor.snapshot():
        if t["ip"] in by_ip:
            info = by_ip[t["ip"]]
            rows.append({**t, "name": info.get("name", ""),
                         "vendor": info.get("vendor", ""), "mac": info.get("mac", ""),
                         "identity_id": id_by_ip.get(t["ip"])})
        elif not t["is_local"] and (t.get("host") or t["bytes"] > 200_000):
            externals.append({**t, "name": t.get("host", ""), "vendor": "", "mac": ""})
    externals.sort(key=lambda x: -x["bytes"])
    return jsonify({"traffic": rows + externals[:25]})

@app.route("/api/traffic/reset", methods=["POST"])
def api_traffic_reset():
    monitor.reset()
    return jsonify({"ok": True})

@app.route("/api/deepscan", methods=["POST"])
def api_deepscan():
    ip = (request.json or {}).get("ip", "")
    if not ip:
        return jsonify({"ok": False, "error": "falta ip"}), 400
    if not scanner.is_local_ip(ip):
        return jsonify({"ok": False, "error": "la IP no pertenece a la red local"}), 400
    result = deepscan.deep_scan(ip)
    # Vuelca SO y puertos como senales/datos persistentes de la identidad.
    if result.get("ok"):
        iid = _identity_for_ip(ip)
        if iid:
            try:
                store.set_ports(iid, result.get("ports") or [])
                identity.resolve(SITE, {
                    "mac": (_online_device_for(iid) or {}).get("mac", ""),
                    "ip": ip, "os_guess": result.get("os", ""),
                    "port_set": [p.get("port") for p in (result.get("ports") or []) if p.get("port")],
                })
            except Exception:
                pass
    return jsonify(result)

@app.route("/api/log")
def api_log():
    ip = request.args.get("ip", "")
    since = int(request.args.get("since", 0) or 0)
    events = monitor.log_since(ip, since)
    latest = events[-1]["seq"] if events else since
    return jsonify({"ip": ip, "events": events, "latest": latest})

@app.route("/api/log/reset", methods=["POST"])
def api_log_reset():
    ip = (request.json or {}).get("ip", "")
    monitor.reset_log(ip)
    return jsonify({"ok": True})

@app.route("/api/device/<int:identity_id>/name", methods=["POST"])
def api_device_name(identity_id):
    if not store.get_identity(identity_id):
        return jsonify({"ok": False, "error": "identidad no encontrada"}), 404
    name = (request.json or {}).get("name", "").strip()
    store.set_identity_label_manual(identity_id, name)
    d = _online_device_for(identity_id)
    if d is not None:
        d["custom_name"] = name
    return jsonify({"ok": True})


@app.route("/api/device/<int:identity_id>/trust", methods=["POST"])
def api_device_trust(identity_id):
    if not store.get_identity(identity_id):
        return jsonify({"ok": False, "error": "identidad no encontrada"}), 404
    store.set_identity_trusted(identity_id, bool((request.json or {}).get("trusted")))
    return jsonify({"ok": True})


@app.route("/api/events")
def api_events():
    evs = store.list_events(SITE, 200)
    labels = {i["id"]: (i.get("label_manual") or i.get("label") or "")
              for i in store.all_identities(SITE)}
    for e in evs:
        e["label"] = labels.get(e.get("identity_id"), "")
    return jsonify({"events": evs})


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    global SITE
    if request.method == "POST":
        data = request.json or {}
        for k in ("tg_token", "tg_chat"):
            if k in data:
                store.set_setting(k, data[k])
        if "alerts_enabled" in data:
            store.set_setting("alerts_enabled", "1" if data["alerts_enabled"] else "0")
        if data.get("site_name"):
            store.set_setting("site_name", data["site_name"])
            SITE = store.ensure_site(data["site_name"])
            _last_scan["known_ids"] = set()
        return jsonify({"ok": True})
    return jsonify({
        "tg_token": store.get_setting("tg_token"),
        "tg_chat": store.get_setting("tg_chat"),
        "alerts_enabled": store.get_setting("alerts_enabled", "0") == "1",
        "site_name": store.get_setting("site_name", "casa"),
    })


@app.route("/api/notify/test", methods=["POST"])
def api_notify_test():
    return jsonify({"ok": notify.test_message()})


@app.route("/api/block/start", methods=["POST"])
def api_block_start():
    payload = request.json or {}
    ip = _target_ip_from_payload(payload)
    if not ip:
        return jsonify({"ok": False, "error": "el equipo esta ausente o la IP no es local"}), 409
    try:
        ok = blocker.block(ip)
        if ok:
            iid = payload.get("identity_id") or _identity_for_ip(ip)
            if iid:
                store.record_event(SITE, int(iid), "bloqueo",
                                   detail=f"bloqueado · {ip}", severity="warn")
        return jsonify({"ok": ok, "blocked": blocker.list_targets(),
                        "error": None if ok else "no se pudo resolver la MAC"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/block/stop", methods=["POST"])
def api_block_stop():
    payload = request.json or {}
    ip = _target_ip_from_payload(payload) or payload.get("ip", "")
    try:
        blocker.unblock(ip)
        return jsonify({"ok": True, "blocked": blocker.list_targets()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/block/status")
def api_block_status():
    return jsonify({"blocked": blocker.list_targets()})


@app.route("/api/export/devices.csv")
def api_export_devices():
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["identity_id", "label", "label_manual", "vendor", "confianza",
                "confiable", "primera_vez", "ultima_vez", "num_senales"])
    for i in store.all_identities(SITE):
        w.writerow([i["id"], i.get("label", ""), i.get("label_manual", ""),
                    i.get("vendor", ""), round(i.get("confidence") or 0.0, 2),
                    i.get("trusted", 0), i.get("first_seen"), i.get("last_seen"),
                    len(store.signals_of(i["id"]))])
    from flask import Response
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=netscope-dispositivos.csv"})


@app.route("/api/export/log.csv")
def api_export_log():
    import csv, io
    ip = request.args.get("ip", "")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "hora", "tipo", "valor"])
    for e in monitor.log_since(ip, 0, limit=100000):
        w.writerow([e["seq"], e["ts"], e["kind"], e["value"]])
    from flask import Response
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=netscope-log-{ip}.csv"})


@app.route("/api/inspect/start", methods=["POST"])
def api_inspect_start():
    ip = _target_ip_from_payload(request.json or {})
    if not ip:
        return jsonify({"ok": False, "error": "el equipo esta ausente o la IP no es local"}), 409
    try:
        if not interceptor.running():
            interceptor.start()
        ok = interceptor.add_target(ip)
        _sync_inspected()
        if not ok:
            if not interceptor.list_targets():
                interceptor.stop()
            return jsonify({"ok": False,
                            "error": "no se pudo resolver la MAC del equipo (reintenta)"}), 500
        return jsonify({"ok": True, "inspecting": interceptor.list_targets()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/inspect/stop", methods=["POST"])
def api_inspect_stop():
    payload = request.json or {}
    ip = _target_ip_from_payload(payload) or payload.get("ip", "")
    try:
        interceptor.remove_target(ip)
        if not interceptor.list_targets():
            interceptor.stop()
        _sync_inspected()
        return jsonify({"ok": True, "inspecting": interceptor.list_targets()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/inspect/status")
def api_inspect_status():
    return jsonify({"running": interceptor.running(),
                    "targets": interceptor.list_targets()})


@app.route("/api/history/traffic")
def api_history_traffic():
    try:
        iid = int(request.args.get("identity_id", ""))
    except ValueError:
        return jsonify({"ok": False, "error": "identity_id invalido"}), 400
    days = min(90, max(1, int(request.args.get("days", 7) or 7)))
    return jsonify({"ok": True, "identity_id": iid,
                    "daily": store.traffic_daily(SITE, iid, days=days)})


# ==== Persistencia de trafico (agregado por ventana) ====================== #
_TRAFFIC_WINDOW = 300         # segundos por ventana (5 min: sobra para grafica diaria)
_traffic_persist_prev = {}    # ip -> (sent_bytes, recv_bytes, packets) de la ultima ventana


def _persist_traffic_window():
    now = time.time()
    window_start = int(now // _TRAFFIC_WINDOW) * _TRAFFIC_WINDOW
    by_ip_identity = {d.get("ip"): iid
                      for iid, d in _last_scan.get("by_identity", {}).items() if d.get("ip")}
    for t in monitor.snapshot():
        ip = t["ip"]
        prev = _traffic_persist_prev.get(ip, (0, 0, 0))
        d_sent = max(0, t["sent_bytes"] - prev[0])
        d_recv = max(0, t["recv_bytes"] - prev[1])
        d_pkts = max(0, t["packets"] - prev[2])
        _traffic_persist_prev[ip] = (t["sent_bytes"], t["recv_bytes"], t["packets"])
        iid = by_ip_identity.get(ip)
        if iid and (d_sent or d_recv):
            try:
                store.add_traffic_window(SITE, window_start, iid, peer_ip="",
                                         peer_host="", proto="", port=0,
                                         bytes_in=d_recv, bytes_out=d_sent, packets=d_pkts)
            except Exception:
                pass


def _resolve_external_names():
    """DNS inverso acotado para peers externos con trafico y sin nombre aun."""
    import socket
    unnamed = [t for t in monitor.snapshot()
               if not t["is_local"] and not t.get("host") and t["bytes"] > 50_000
               and not monitor.ptr_tried(t["ip"])]
    for t in sorted(unnamed, key=lambda x: -x["bytes"])[:15]:
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(0.8)
            monitor.note_name(t["ip"], socket.gethostbyaddr(t["ip"])[0])
        except Exception:
            monitor.note_name(t["ip"], "")   # marca "sin PTR" para no reintentar
        finally:
            socket.setdefaulttimeout(old)


def _traffic_persist_loop():
    last_purge = 0.0
    while True:
        time.sleep(_TRAFFIC_WINDOW)
        try:
            _persist_traffic_window()
            _resolve_external_names()
        except Exception:
            pass
        if time.time() - last_purge > 6 * 3600:
            last_purge = time.time()
            try:
                store.purge_observations()
                store.purge_traffic()
            except Exception:
                pass


# ==== Arranque ============================================================= #
def _startup():
    global SITE
    store.init()
    SITE = store.ensure_site(store.get_setting("site_name", "casa"))
    # Cache instantanea desde la BD (fabricantes/nombres ya conocidos)
    scanner.seed_caches()
    # Descarga la base de fabricantes UNA vez, sin bloquear escaneos
    threading.Thread(target=scanner.prewarm_vendors, daemon=True).start()
    scanner.mdns.start()
    monitor.start()
    # Primer escaneo + bucle automatico que mantiene la lista fresca sola
    threading.Thread(target=_background_scan, daemon=True).start()
    threading.Thread(target=_auto_scan_loop, daemon=True).start()
    threading.Thread(target=_traffic_persist_loop, daemon=True).start()

def _shutdown(*_):
    # Restaura tablas ARP y detiene la captura antes de salir: si no,
    # los equipos interceptados/bloqueados quedan sin internet hasta que
    # caduque su cache ARP.
    for stop in (interceptor.stop, blocker.stop, monitor.stop, scanner.mdns.stop):
        try:
            stop()
        except Exception:
            pass
    raise SystemExit(0)


def _serve():
    try:
        from waitress import serve
        print("  (servidor: waitress)")
        serve(app, host="127.0.0.1", port=5000, threads=8, _quiet=True)
    except Exception:
        print("  (servidor: Flask dev - instala waitress para mas velocidad)")
        app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)


if __name__ == "__main__":
    if not platform_setup.is_admin():
        print("NetScope necesita privilegios de administrador/root.")
        print("Solicitando elevacion (acepta UAC / escribe tu contrasena)...")
        if not platform_setup.relaunch_as_admin():
            sys.exit(0)

    print("=" * 60)
    print("  NetScope - consola de red local")
    print("  Abre:  http://127.0.0.1:5000")
    print("=" * 60)
    platform_setup.print_report()
    signal.signal(signal.SIGINT, _shutdown)
    try:
        signal.signal(signal.SIGTERM, _shutdown)
    except Exception:
        pass
    _startup()
    _serve()
