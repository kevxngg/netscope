"""
deepscan.py — Escaneo profundo con nmap (bajo demanda, por dispositivo).

nmap hace lo que a mano queda mal:
  - Deteccion del sistema operativo (Windows / iOS / Android / Linux...)
  - Puertos abiertos
  - Servicio y version que corre en cada puerto

Se ejecuta cuando pides analizar UN equipo (no toda la red), que es lo correcto:
un escaneo -O -sV es pesado y lento para lanzarlo contra todos a la vez.

Requiere nmap instalado y permisos de admin/root (la deteccion de SO los pide).
"""

import shutil
import subprocess
import xml.etree.ElementTree as ET
import ipaddress


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def deep_scan(ip: str, timeout: int = 180) -> dict:
    try:
        ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return {"ok": False, "error": "la IP no es valida."}
    if not nmap_available():
        return {"ok": False, "error": "nmap no esta instalado en este equipo."}

    cmd = ["nmap", "-O", "--osscan-guess", "-sV", "-T4", "-oX", "-", ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "nmap tardo demasiado (timeout)."}
    except Exception as e:
        return {"ok": False, "error": f"no se pudo ejecutar nmap: {e}"}

    if proc.returncode != 0:
        detail = proc.stderr.strip() or "nmap devolvio un error."
        return {"ok": False, "error": detail}

    return _parse_xml(proc.stdout, ip)


def _parse_xml(xml_text: str, ip: str) -> dict:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return {"ok": False, "error": "no se pudo interpretar la salida de nmap."}

    host = root.find("host")
    if host is None:
        return {"ok": True, "ip": ip, "os": "", "os_accuracy": "", "ports": [],
                "note": "El host no respondio al escaneo profundo."}

    # ---- Sistema operativo ----
    os_name, os_acc = "", ""
    osnode = host.find("os")
    if osnode is not None:
        match = osnode.find("osmatch")
        if match is not None:
            os_name = match.get("name", "")
            os_acc = match.get("accuracy", "")

    # ---- Puertos / servicios ----
    ports = []
    portsnode = host.find("ports")
    if portsnode is not None:
        for p in portsnode.findall("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": p.get("portid", ""),
                "proto": p.get("protocol", ""),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })

    return {"ok": True, "ip": ip, "os": os_name, "os_accuracy": os_acc, "ports": ports}
