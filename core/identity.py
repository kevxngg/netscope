"""
core/identity.py — Resolucion de identidad de dispositivos.

EL PROBLEMA que resuelve este modulo:
    Los telefonos y portatiles modernos rotan su MAC por red (privacidad). Si la
    identidad de un equipo fuera su MAC, cada reconexion crearia un "equipo
    nuevo" y el histgrico se llenaria de fantasmas. Aqui una identidad se define
    por la COMBINACION de varias senales, no por una sola.

COMO funciona:
    1. De cada observacion (ARP/DHCP/mDNS/nmap) se extraen SENALES con un peso.
    2. Se buscan identidades que ya tengan alguna de esas senales.
    3. Una candidata "gana" si cumple la REGLA DE FUSION (abajo).
    4. Si ninguna cumple, se crea una identidad nueva.
    5. Las senales de la observacion se funden en la identidad elegida.

Una identidad con etiqueta MANUAL esta CONGELADA: no se re-evalua ni se le
cambia la etiqueta automatica. Es mas barato y mas exacto dejar que el usuario
corrija a mano que perseguir un algoritmo perfecto.
"""

import threading
from collections import defaultdict

from . import store

# resolve() hace varias lecturas y escrituras que deben ser atomicas entre si
# (leer candidatas -> decidir -> crear/fundir). Sin esto, dos escaneos a la vez
# podrian crear dos identidades para el mismo equipo.
_resolve_lock = threading.Lock()

# Marcadores de "no hay nombre". No sirven ni para fundir ni como etiqueta.
_NON_NAMES = {"", "(sin nombre)", "unknown", "desconocido", "localhost",
              "localhost.localdomain", "intel_ce_linux"}

# Hostnames que muchos equipos comparten de fabrica: valen como etiqueta visible
# ("iPhone" es mejor que nada) pero NO identifican a un equipo concreto.
_GENERIC_HOSTNAMES = _NON_NAMES | {
    "android", "iphone", "ipad", "ipod", "macbook", "macbook-pro",
    "macbook-air", "galaxy", "pixel", "windows-phone", "raspberrypi",
    "amazon", "echo", "chromecast", "google-home", "google-nest-hub",
    "dhcp", "new-host", "espressif",
}


def usable_label(name) -> str:
    """Devuelve el nombre si sirve como etiqueta visible, o '' si es un marcador
    de 'sin nombre'. Evita guardar el literal '(sin nombre)' como label."""
    name = (name or "").strip()
    return "" if name.lower() in _NON_NAMES else name


# --------------------------------------------------------------------------- #
#  Pesos de cada tipo de senal (de mas fuerte a mas debil)
# --------------------------------------------------------------------------- #
WEIGHTS = {
    "mac":        1.0,   # MAC real (grabada de fabrica): identifica una NIC unica
    "hostname":   0.9,   # el usuario lo personaliza -> muy distintivo
    "port_set":   0.5,   # conjunto de puertos abiertos (estable en equipos fijos)
    "dhcp_fp":    0.5,   # huella DHCP: el orden de opciones delata el SO
    "os":         0.4,   # SO detectado por nmap
    "schedule":   0.2,   # patron horario (solo desempate)
    "mac_random": 0.1,   # MAC randomizada: sirve dentro de una sesion, no entre ellas
}

# Suma teorica maxima para normalizar la confianza a 0..1. "mac" y "mac_random"
# son excluyentes (una observacion aporta una o la otra), asi que solo cuenta la
# fuerte; si no, la confianza nunca llegaria a 1.0 de forma organica.
_MAX_WEIGHT = sum(w for k, w in WEIGHTS.items() if k != "mac_random")


# --------------------------------------------------------------------------- #
#  Deteccion de MAC randomizada
# --------------------------------------------------------------------------- #
def is_randomized_mac(mac: str) -> bool:
    """
    Una MAC es 'administrada localmente' (casi siempre = randomizada) si el bit 1
    (0x02) del primer octeto esta encendido. En hex, el segundo digito del primer
    octeto sera 2, 6, A o E en el caso normal (unicast + local).
    """
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


# --------------------------------------------------------------------------- #
#  Extraccion de senales de una observacion
# --------------------------------------------------------------------------- #
def signals_from_observation(obs: dict):
    """
    obs: dict con posibles claves mac, hostname, dhcp_fp, os_guess, port_set.
    Devuelve lista de (kind, value, weight) normalizadas y no vacias.
    """
    out = []

    mac = (obs.get("mac") or "").lower().strip()
    if mac:
        if is_randomized_mac(mac):
            out.append(("mac_random", mac, WEIGHTS["mac_random"]))
        else:
            out.append(("mac", mac, WEIGHTS["mac"]))

    host = (obs.get("hostname") or "").strip()
    # descarta nombres genericos que NO distinguen un equipo de otro del mismo
    # modelo (dos "iPhone" en la red no son el mismo telefono).
    if host and host.lower() not in _GENERIC_HOSTNAMES:
        out.append(("hostname", host, WEIGHTS["hostname"]))

    dhcp = (obs.get("dhcp_fp") or "").strip()
    if dhcp:
        out.append(("dhcp_fp", dhcp, WEIGHTS["dhcp_fp"]))

    os_guess = (obs.get("os_guess") or "").strip()
    if os_guess:
        out.append(("os", os_guess, WEIGHTS["os"]))

    port_set = obs.get("port_set")
    if port_set:
        # normaliza a "22,80,443" ordenado para que sea comparable
        if isinstance(port_set, (list, tuple, set)):
            port_set = ",".join(str(p) for p in sorted(int(x) for x in port_set))
        out.append(("port_set", str(port_set), WEIGHTS["port_set"]))

    return out


# --------------------------------------------------------------------------- #
#  Regla de fusion
# --------------------------------------------------------------------------- #
def _passes_fusion(matched_kinds: set) -> bool:
    """
    Dos observaciones son el mismo equipo si:
      - coincide una MAC real, el hostname (ya filtrado de genericos), o LA MISMA
        MAC randomizada  -> identificador fuerte, o
      - coinciden DOS senales independientes que no sean ambas "de sistema"
        (dhcp_fp y os van correlados: dos moviles del mismo modelo/version los
        comparten, asi que juntos NO bastan), o
      - coinciden tres o mas senales distintas de `os`.
    Una MAC randomizada solo colisiona consigo misma (46 bits aleatorios); el
    matiz "no sirve entre sesiones" lo da que al reconectarse la MAC cambia y ya
    no coincide, no que haya que ignorar una coincidencia exacta.
    """
    if matched_kinds & {"mac", "mac_random", "hostname"}:
        return True
    # combinaciones de señales debiles pero INDEPENDIENTES entre si
    if "dhcp_fp" in matched_kinds and "port_set" in matched_kinds:
        return True
    if "port_set" in matched_kinds and "schedule" in matched_kinds:
        return True
    if len(matched_kinds - {"os"}) >= 3:
        return True
    return False


# --------------------------------------------------------------------------- #
#  Resolucion
# --------------------------------------------------------------------------- #
def resolve(site_id: int, obs: dict) -> int:
    """
    Devuelve el identity_id (existente o recien creado) para esta observacion,
    y funde en el las senales observadas.
    """
    signals = signals_from_observation(obs)
    if not signals:
        # sin ninguna senal util no podemos identificar nada; crea identidad suelta
        with _resolve_lock:
            return store.create_identity(site_id, label=(obs.get("ip") or ""))

    with _resolve_lock:
        # 1) reunir candidatas por senal coincidente
        matched = defaultdict(set)      # identity_id -> set de kinds que coinciden
        weight_by_id = defaultdict(float)
        for kind, value, weight in signals:
            for iid in store.identities_matching_signal(site_id, kind, value):
                matched[iid].add(kind)
                weight_by_id[iid] += weight

        # 2) elegir la mejor candidata que pase la regla de fusion
        best_id, best_score = None, -1.0
        for iid, kinds in matched.items():
            if _passes_fusion(kinds) and weight_by_id[iid] > best_score:
                best_id, best_score = iid, weight_by_id[iid]

        # 3) crear si no hay candidata valida
        if best_id is None:
            best_id = store.create_identity(
                site_id, label=usable_label(obs.get("hostname")))

        # 4) fundir senales y refrescar metadatos (respeta identidades congeladas)
        frozen = store.is_frozen(best_id)
        for kind, value, weight in signals:
            store.upsert_signal(best_id, kind, value, weight)
        store.touch_identity(best_id)

        if not frozen:
            # Etiqueta automatica. Un nombre generico ("iPhone") vale como
            # etiqueta visible, pero NO debe pisar uno mas especifico que ya
            # tengamos ("iPhone-de-Ana"): solo se usa si no hay etiqueta aun.
            host = usable_label(obs.get("hostname"))
            if host:
                if host.lower() not in _GENERIC_HOSTNAMES:
                    store.set_identity_label_auto(best_id, host)
                elif not (store.get_identity(best_id) or {}).get("label"):
                    store.set_identity_label_auto(best_id, host)
            # confianza: suma de pesos de las senales de la identidad, normalizada
            total = sum(s["weight"] for s in store.signals_of(best_id))
            store.set_identity_confidence(best_id, min(1.0, total / _MAX_WEIGHT))

    return best_id
