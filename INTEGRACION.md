# Integración del nuevo core — Fase 1

> **Estado: INTEGRADA.** `app.py` ya usa `core/store` + `core/identity`; `storage.py`
> se eliminó. El flujo descrito abajo es el que corre hoy. Además ya funcionan el
> colector DHCP pasivo (`sniffer.py`), el volcado de SO/puertos de nmap a la
> identidad (`/api/deepscan`), la persistencia de tráfico por ventana y el
> nombrado de IPs externas. Pruebas: `python tests/test_identity.py`.
>
> El front enlaza por `identity_id` (`/device/<id>`, no `/device/<ip>`).

Este paquete `core/` reemplaza al viejo `storage.py`. Trae el modelo de
identidad y sitios que decidimos en el plan. **Ya está probado**: el criterio de
la Fase 1 (un teléfono con MAC randomizada que se reconecta tres veces sigue
siendo una identidad) pasa. Con 9 MACs distintas en la prueba, el motor produjo
6 identidades reales en vez de 9 fantasmas.

## Qué hace cada archivo

- **`core/store.py`** — capa de datos. Esquema nuevo (identities, identity_signals,
  sites, observations, traffic_samples, ports, events). SQLite en WAL. Solo
  persiste; no decide nada.
- **`core/identity.py`** — la inteligencia. Detecta MAC randomizada, extrae
  señales de cada observación y las funde en la identidad correcta.

## Cómo se conecta con lo que ya tienes

Hoy, en `app.py`, la función `_enrich_and_store()` hace esto por cada dispositivo:

```python
is_new = storage.upsert_device(d["mac"], d["ip"], d.get("vendor",""), d.get("name",""))
```

Eso es lo que hay que cambiar. El flujo nuevo es:

```python
from core import store, identity

SITE = store.ensure_site("casa")   # una vez al arrancar; "empresa" en la otra instalación

# por cada dispositivo enriquecido:
obs = {
    "mac": d["mac"],
    "ip": d["ip"],
    "hostname": d.get("name", ""),
    "vendor": d.get("vendor", ""),
    # dhcp_fp y os_guess llegan cuando existan los colectores DHCP y nmap
}
iid = identity.resolve(SITE, obs)          # <- resuelve o crea la identidad
store.record_observation(SITE, "arp", identity_id=iid, mac=d["mac"],
                         ip=d["ip"], hostname=d.get("name",""),
                         vendor=d.get("vendor",""))
d["identity_id"] = iid                       # para que la UI enlace por identidad
```

La detección de "dispositivo nuevo" ahora es **identidad nueva**, no MAC nueva:
compara el `iid` devuelto contra los que ya conocías, o mira si
`store.get_identity(iid)["first_seen"]` es de hace segundos.

## Lo que todavía NO alimenta el motor (y por qué está bien)

El motor ya acepta señales `dhcp_fp`, `os` y `port_set`, pero el código actual
no las produce. Eso es trabajo de fases siguientes:

- **`dhcp_fp`** → un colector DHCP pasivo (sniff de opciones DHCP). Es la señal
  que permite re-enlazar un teléfono cuando SOLO cambió la MAC. Vale mucho.
- **`os` / `port_set`** → ya casi los tienes: `deepscan.py` saca SO y puertos con
  nmap. Solo falta volcarlos como señales con `store.set_ports()` y pasando
  `os_guess`/`port_set` en la observación.

Mientras tanto, con MAC + hostname el motor ya colapsa la mayoría de
reconexiones. El DHCP fingerprint lo hace redondo.

## Migración de datos

No hay. Empiezas la BD limpia (así lo decidiste). El `netscope.db` viejo se
puede borrar; `store.init()` crea el esquema nuevo solo al arrancar.

## Orden sugerido para Claude Code

1. Copiar `core/` dentro de `netscope-main/`.
2. En `app.py`: `import` del nuevo `store`/`identity`, crear el sitio al arrancar,
   cambiar `_enrich_and_store()` al flujo de arriba.
3. Cambiar las rutas de la API que leían `storage.all_devices()` para que lean
   `store.all_identities(SITE)` y expongan `identity_id`.
4. Ajustar el front (`devices.js`, `device.js`) para enlazar por `identity_id`
   en vez de por `mac`.
5. Borrar `storage.py` viejo cuando nada lo importe.

Los pasos 3 y 4 son mecánicos. El 2 es el único con enjundia.
