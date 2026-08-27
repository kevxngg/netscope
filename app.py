"""
app.py - Servidor de NetScope (multi-pagina + API).

Sirve con waitress (servidor WSGI de produccion, mucho mas fluido que el server
de desarrollo de Flask) si esta disponible; si no, cae al de Flask.
"""

import signal
import sys
import threading
import time

from flask import Flask, jsonify, render_template, request

import scanner
import deepscan
import platform_setup
import wifi
import speedtest
import storage
import notify
from sniffer import monitor
from mitm import interceptor, blocker

app = Flask(__name__)

_last_scan = {"devices": [], "gateway": "", "ts": 0, "enriching": False,
              "error": ""}
_scan_lock = threading.Lock()
_enrich_lock = threading.Lock()
_summary_cache = {"data": None, "ts": 0.0}
_SUMMARY_TTL = 3.0
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
        # conserva nombre personalizado ya guardado
        for d in devices:
            cn = storage.get_custom_name(d["mac"])
            if cn:
                d["custom_name"] = cn
        _last_scan["devices"] = devices
        _last_scan["gateway"] = gateway
        _last_scan["ts"] = time.time()
        _last_scan["error"] = ""
        monitor.set_local_ips(list(own_ips))
    return devices, own_ips


def _enrich_and_store(devices, own_ips):
    """FASE 2: resuelve nombres/fabricantes (muta los dicts ya publicados) y guarda."""
    with _enrich_lock:
        _last_scan["enriching"] = True
        try:
            was_empty = storage.device_count() == 0
            scanner.enrich_all(devices, own_ips=own_ips)
            for d in devices:
                is_new = storage.upsert_device(
                    d["mac"], d["ip"], d.get("vendor", ""), d.get("name", ""))
                cn = storage.get_custom_name(d["mac"])
                if cn:
                    d["custom_name"] = cn
                if is_new and not was_empty:
                    storage.record_event("nuevo", d["mac"], d["ip"], d.get("name", ""))
                    try:
                        notify.notify_new_device(
                            cn or d.get("name", ""), d["ip"], d.get("vendor", ""))
                    except Exception:
                        pass
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


def _device_by_ip(ip):
    return next((d for d in _last_scan["devices"] if d["ip"] == ip), None)


def _sync_inspected():
    monitor.set_inspected(set(interceptor.list_targets()))


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

@app.route("/device/<ip>")
def page_device(ip):
    return render_template("device.html", seccion="devices", ip=ip)

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
    data = {
        "devices": len(_last_scan["devices"]),
        "inspecting": interceptor.list_targets(),
        "traffic_ips": monitor.summary()["traffic_ips"],
        "gateway": _last_scan["gateway"],
        "os": r["os"], "admin": r["admin"], "nmap": r["nmap"]["ok"],
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

@app.route("/api/speedtest", methods=["POST"])
def api_speedtest():
    return jsonify(speedtest.run_speedtest())

@app.route("/api/networks")
def api_networks():
    nets = [{"iface": i, "cidr": c, "ip": ip} for i, c, ip in scanner.get_local_networks()]
    return jsonify({"networks": nets, "nmap": deepscan.nmap_available()})

@app.route("/api/devices")
def api_devices():
    return jsonify({"devices": _last_scan["devices"],
                    "gateway": _last_scan["gateway"], "ts": _last_scan["ts"],
                    "enriching": _last_scan.get("enriching", False),
                    "error": _last_scan.get("error", "")})

@app.route("/api/device/<ip>")
def api_device(ip):
    d = _device_by_ip(ip)
    if not d:
        return jsonify({"ok": False, "error": "dispositivo no encontrado"}), 404
    return jsonify({"ok": True, "device": d,
                    "inspecting": ip in interceptor.list_targets()})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        devices, own_ips = _do_scan_fast()
        # nombres/fabricantes se resuelven en segundo plano (la vista se rellena sola)
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
    rows = []
    for t in monitor.snapshot():
        info = by_ip.get(t["ip"], {})
        rows.append({**t, "name": info.get("name", ""),
                     "vendor": info.get("vendor", ""), "mac": info.get("mac", "")})
    return jsonify({"traffic": rows})

@app.route("/api/traffic/reset", methods=["POST"])
def api_traffic_reset():
    monitor.reset()
    return jsonify({"ok": True})

@app.route("/api/deepscan", methods=["POST"])
def api_deepscan():
    ip = (request.json or {}).get("ip", "")
    if not ip:
        return jsonify({"ok": False, "error": "falta ip"}), 400
    return jsonify(deepscan.deep_scan(ip))

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

@app.route("/api/device/<ip>/name", methods=["POST"])
def api_device_name(ip):
    d = _device_by_ip(ip)
    if not d:
        return jsonify({"ok": False, "error": "dispositivo no encontrado"}), 404
    name = (request.json or {}).get("name", "").strip()
    storage.set_custom_name(d["mac"], name)
    d["custom_name"] = name
    return jsonify({"ok": True})


@app.route("/api/device/<ip>/trust", methods=["POST"])
def api_device_trust(ip):
    d = _device_by_ip(ip)
    if not d:
        return jsonify({"ok": False, "error": "no encontrado"}), 404
    storage.set_trusted(d["mac"], bool((request.json or {}).get("trusted")))
    return jsonify({"ok": True})


@app.route("/api/events")
def api_events():
    return jsonify({"events": storage.list_events()})


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        data = request.json or {}
        for k in ("tg_token", "tg_chat"):
            if k in data:
                storage.set_setting(k, data[k])
        if "alerts_enabled" in data:
            storage.set_setting("alerts_enabled", "1" if data["alerts_enabled"] else "0")
        return jsonify({"ok": True})
    return jsonify({
        "tg_token": storage.get_setting("tg_token"),
        "tg_chat": storage.get_setting("tg_chat"),
        "alerts_enabled": storage.get_setting("alerts_enabled", "0") == "1",
    })


@app.route("/api/notify/test", methods=["POST"])
def api_notify_test():
    return jsonify({"ok": notify.test_message()})


@app.route("/api/block/start", methods=["POST"])
def api_block_start():
    ip = (request.json or {}).get("ip", "")
    try:
        ok = blocker.block(ip)
        if ok:
            d = _device_by_ip(ip)
            storage.record_event("bloqueo", d["mac"] if d else "", ip, "bloqueado")
        return jsonify({"ok": ok, "blocked": blocker.list_targets(),
                        "error": None if ok else "no se pudo resolver la MAC"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/block/stop", methods=["POST"])
def api_block_stop():
    ip = (request.json or {}).get("ip", "")
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
    w.writerow(["mac", "ip", "vendor", "auto_name", "custom_name",
                "first_seen", "last_seen", "seen_count", "trusted"])
    for d in storage.all_devices():
        w.writerow([d["mac"], d["ip"], d["vendor"], d["auto_name"], d["custom_name"],
                    d["first_seen"], d["last_seen"], d["seen_count"], d["trusted"]])
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
    ip = (request.json or {}).get("ip", "")
    if not ip:
        return jsonify({"ok": False, "error": "falta ip"}), 400
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
    ip = (request.json or {}).get("ip", "")
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


# ==== Arranque ============================================================= #
def _startup():
    # Cache instantanea desde la BD (fabricantes/nombres ya conocidos)
    scanner.seed_caches_from_storage()
    # Descarga la base de fabricantes UNA vez, sin bloquear escaneos
    threading.Thread(target=scanner.prewarm_vendors, daemon=True).start()
    scanner.mdns.start()
    monitor.start()
    # Primer escaneo + bucle automatico que mantiene la lista fresca sola
    threading.Thread(target=_background_scan, daemon=True).start()
    threading.Thread(target=_auto_scan_loop, daemon=True).start()

def _shutdown(*_):
    try:
        interceptor.stop()
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
