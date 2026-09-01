"""
test_identity.py — Pruebas del motor de identidad (core/identity.py + core/store.py).

Ejecutar sin pytest:   python tests/test_identity.py
Sale con codigo != 0 si algo falla.

Usa una BD SQLite temporal (no toca netscope.db).
"""

import os
import sys
import tempfile
import atexit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import store, identity  # noqa: E402

_temp_paths = []


@atexit.register
def _cleanup_temp_dbs():
    for path in _temp_paths:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def _fresh_db():
    fd, path = tempfile.mkstemp(prefix="netscope-test-", suffix=".db")
    os.close(fd)
    os.remove(path)  # que lo cree el esquema
    store.DB = path
    store.init()
    _temp_paths.append(path)
    return path


_results = []


def check(name, cond):
    _results.append((name, bool(cond)))
    print(f"  [{'OK' if cond else 'XX'}] {name}")


def test_mac_randomizada_reconecta():
    """Un movil con MAC aleatoria que se reconecta 3 veces = UNA identidad."""
    _fresh_db()
    site = store.ensure_site("test")
    ids = set()
    for mac in ("a2:11:22:33:44:01", "a6:99:88:77:66:02", "ae:55:44:33:22:03"):
        ids.add(identity.resolve(site, {"mac": mac, "ip": "192.168.1.50",
                                        "hostname": "Pixel-de-Kevin"}))
    check("MAC randomizada x3 -> 1 identidad", len(ids) == 1)


def test_revinculo_por_dhcp_y_puertos():
    """Cambia SOLO la MAC (nueva random) pero coinciden huella DHCP Y conjunto de
    puertos (dos señales independientes) -> se re-vincula a la misma identidad."""
    _fresh_db()
    site = store.ensure_site("test")
    a = identity.resolve(site, {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.5",
                                "dhcp_fp": "1,121,3,6,15,119,252",
                                "port_set": [22, 8080, 9100]})
    b = identity.resolve(site, {"mac": "b2:00:00:00:00:99", "ip": "10.0.0.5",
                                "dhcp_fp": "1,121,3,6,15,119,252",
                                "port_set": [9100, 22, 8080]})
    check("re-vinculo por dhcp_fp + port_set -> misma identidad", a == b)


def test_dos_moviles_mismo_so_no_se_fusionan():
    """Dos móviles distintos del mismo modelo/versión comparten huella DHCP y SO
    pero NO tienen nombre ni puertos: NO deben fusionarse."""
    _fresh_db()
    site = store.ensure_site("test")
    a = identity.resolve(site, {"mac": "aa:00:00:00:00:01",
                                "dhcp_fp": "1,3,6,15,119,252", "os_guess": "iOS 17"})
    b = identity.resolve(site, {"mac": "b2:00:00:00:00:02",
                                "dhcp_fp": "1,3,6,15,119,252", "os_guess": "iOS 17"})
    check("dos iPhone iOS17 sin nombre -> 2 identidades", a != b)


def test_equipos_distintos_no_se_fusionan():
    _fresh_db()
    site = store.ensure_site("test")
    a = identity.resolve(site, {"mac": "aa:bb:cc:00:00:01", "hostname": "PC-Salon"})
    b = identity.resolve(site, {"mac": "aa:bb:cc:00:00:02", "hostname": "PC-Oficina"})
    check("dos equipos distintos -> 2 identidades", a != b)


def test_misma_mac_random_en_sesion():
    """Un equipo sin nombre con MAC aleatoria escaneado 3 veces en la misma
    sesion (la MAC aun no rotó) = UNA identidad, no un fantasma por escaneo."""
    _fresh_db()
    site = store.ensure_site("test")
    ids = {identity.resolve(site, {"mac": "c2:aa:bb:cc:dd:ee", "ip": "10.0.0.9"})
           for _ in range(3)}
    check("misma MAC randomizada x3 -> 1 identidad", len(ids) == 1)


def test_dos_iphone_genericos_no_se_fusionan():
    """Dos telefonos distintos que anuncian el hostname generico 'iPhone'
    NO deben colapsar en una sola identidad."""
    _fresh_db()
    site = store.ensure_site("test")
    a = identity.resolve(site, {"mac": "aa:bb:cc:dd:ee:f1", "hostname": "iPhone"})
    b = identity.resolve(site, {"mac": "aa:bb:cc:dd:ee:f2", "hostname": "iPhone"})
    check("dos 'iPhone' genericos -> 2 identidades", a != b)


def test_sin_nombre_no_se_guarda_como_etiqueta():
    """Un equipo cuyo nombre no se pudo resolver llega como '(sin nombre)'.
    Eso NO debe quedar guardado como etiqueta (si no, el resumen lo contaria
    como equipo 'con nombre')."""
    _fresh_db()
    site = store.ensure_site("test")
    iid = identity.resolve(site, {"mac": "aa:bb:cc:00:00:21", "ip": "10.0.0.7",
                                  "hostname": "(sin nombre)"})
    check("'(sin nombre)' no se guarda como label",
          not (store.get_identity(iid)["label"] or ""))


def test_generico_no_pisa_nombre_especifico():
    """Un nombre generico ('iPhone') no debe sustituir a uno mas especifico
    ya conocido ('iPhone-de-Ana')."""
    _fresh_db()
    site = store.ensure_site("test")
    mac = "aa:bb:cc:00:00:31"
    iid = identity.resolve(site, {"mac": mac, "hostname": "iPhone-de-Ana"})
    identity.resolve(site, {"mac": mac, "hostname": "iPhone"})
    check("generico no pisa nombre especifico",
          store.get_identity(iid)["label"] == "iPhone-de-Ana")


def test_identidad_congelada():
    _fresh_db()
    site = store.ensure_site("test")
    iid = identity.resolve(site, {"mac": "aa:bb:cc:00:00:0a", "hostname": "portatil"})
    store.set_identity_label_manual(iid, "Portatil de Kevin")
    identity.resolve(site, {"mac": "aa:bb:cc:00:00:0a", "hostname": "otro-nombre"})
    ident = store.get_identity(iid)
    check("etiqueta manual no la pisa un hostname nuevo",
          ident["label_manual"] == "Portatil de Kevin")


if __name__ == "__main__":
    for fn in (test_mac_randomizada_reconecta, test_revinculo_por_dhcp_y_puertos,
               test_dos_moviles_mismo_so_no_se_fusionan,
               test_equipos_distintos_no_se_fusionan, test_misma_mac_random_en_sesion,
               test_dos_iphone_genericos_no_se_fusionan,
               test_sin_nombre_no_se_guarda_como_etiqueta,
               test_generico_no_pisa_nombre_especifico, test_identidad_congelada):
        print(fn.__doc__.strip().splitlines()[0] if fn.__doc__ else fn.__name__)
        fn()
    ok = sum(1 for _, c in _results if c)
    print(f"\n{ok}/{len(_results)} pruebas OK")
    sys.exit(0 if ok == len(_results) else 1)
