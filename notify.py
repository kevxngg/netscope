"""
notify.py - Notificaciones por Telegram (opcional).

Configura el token del bot y el chat_id en la pagina de Ajustes. Se usa para
avisar cuando aparece un dispositivo desconocido en la red.
"""

import urllib.parse
import urllib.request
from html import escape

from core import store


def send_telegram(token, chat_id, text):
    if not token or not chat_id:
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat_id, "text": text, "parse_mode": "HTML"
        }).encode()
        with urllib.request.urlopen(
                urllib.request.Request(url, data=data), timeout=6):
            pass
        return True
    except Exception:
        return False


def alerts_enabled():
    return store.get_setting("alerts_enabled", "0") == "1"


def notify_new_device(name, ip, vendor):
    if not alerts_enabled():
        return
    token = store.get_setting("tg_token")
    chat = store.get_setting("tg_chat")
    text = (f"\U0001F6A8 <b>NetScope</b>\nNuevo dispositivo en la red\n"
            f"Nombre: {escape(str(name or '(sin nombre)'))}\n"
            f"IP: {escape(str(ip))}\n"
            f"Fabricante: {escape(str(vendor or '-'))}")
    send_telegram(token, chat, text)


def test_message():
    token = store.get_setting("tg_token")
    chat = store.get_setting("tg_chat")
    return send_telegram(token, chat, "\u2705 NetScope: notificaciones configuradas correctamente.")
