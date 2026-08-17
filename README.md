# NetScope

**Consola de administración para tu propia red Wi-Fi/LAN.**
Escanea los dispositivos conectados, los muestra como un árbol con nombre,
fabricante, IP y MAC, mide el tráfico de cada uno en vivo y te deja analizar o
interceptar un equipo concreto para ver a dónde habla. Todo desde una interfaz
web tipo terminal que corre en tu propia máquina.

> Uso legal. Úsala solo en redes que administras o donde tengas permiso
> explícito. Escanear o interceptar redes ajenas es ilegal en la mayoría de
> países.

---

## ¿Qué es?

Una herramienta local (no sube nada a internet) para vigilar y administrar tu
red. Pensada para saber en todo momento qué hay conectado, detectar equipos
desconocidos y ver cómo se comporta cada dispositivo, tanto en la red de casa
como en la de la empresa.

## ¿Qué hace?

| Función | Descripción |
|---|---|
| **Árbol de la red** | El router como raíz y cada dispositivo como rama, con nombre, fabricante, IP y MAC. |
| **Nombres reales** | Combina mDNS/Bonjour, DNS inverso, NetBIOS y fabricante (OUI) para identificar cada equipo. |
| **Escaneo profundo** | Con `nmap`: sistema operativo, puertos abiertos y servicio/versión de cada equipo. |
| **Tráfico por dispositivo** | Bytes y paquetes en vivo, con barras de subida y bajada. |
| **Intercepción selectiva** | Ver todo el tráfico de un equipo elegido y a qué dominios habla. |
| **Autodetección del sistema** | Reconoce el SO al arrancar y avisa de permisos y dependencias que falten. |
| **Instalación automática** | `run.py` instala dependencias y nmap, y arranca con privilegios de administrador. |
| **Interfaz multipágina** | Panel estilo GitHub (barra lateral) con una ruta por sección y fuente SF Pro. |
| **Log de conexiones** | Registro en vivo de a dónde habla cada equipo: DNS, SNI (TLS) y URL en HTTP. |
| **Info Wi-Fi** | Nombre de red (SSID), señal, canal y banda de la red a la que estás conectado. |
| **Test de velocidad** | Latencia, descarga y subida (corre en el navegador, estilo fast.com). |
| **Historial** | Registro de eventos y aviso cuando aparece un dispositivo desconocido. |
| **Nombres personalizados** | Renombra un equipo (ej. "Celular de Kevin"); se guarda en SQLite. |
| **Bloquear equipos** | Corta el acceso a internet de un equipo desde la consola (ARP). |
| **Notificaciones** | Avisos por Telegram cuando entra un equipo nuevo (opcional). |
| **Exportar** | Descarga dispositivos y logs en CSV. |
| **Gráfica en vivo** | Tráfico total de la red en una línea de tiempo. |

---

## Requisitos

- **Python 3.8+**
- Permisos de **administrador / root** (el escaneo y la captura los necesitan; NetScope los pide solo)
- **nmap** — para el escaneo profundo (lo instala `run.py` si falta)

| SO | Gestor que usa `run.py` | Notas |
|---|---|---|
| **Windows** | winget | nmap instala también Npcap (necesario para la captura) |
| **macOS** | Homebrew | requiere tener [Homebrew](https://brew.sh) |
| **Linux** | apt / dnf / pacman / zypper | usa `sudo` para instalar |

---

## Instalación y uso

### Opción A — Automática (recomendada)

Un solo comando que crea un entorno virtual, instala ahí las dependencias,
instala **nmap** si falta y arranca NetScope con permisos de administrador:

```bash
git clone https://github.com/kevxngg/netscope.git
cd netscope

python run.py         # Windows
python3 run.py        # macOS / Linux
```

`run.py` detecta tu sistema y usa su gestor de paquetes (**winget** en Windows,
**Homebrew** en macOS, **apt/dnf/pacman** en Linux). Puede pedirte confirmación
(UAC) o contraseña. Si algo no se puede instalar solo, te muestra el comando
exacto para hacerlo a mano.

> **¿Por qué un venv?** Al elevar a administrador, el proceso corre en otra
> "sesión" y **no ve los paquetes instalados en tu usuario**. NetScope usa un
> entorno virtual (`venv/`) y siempre llama al Python del venv **por su ruta
> completa**, que sí es visible para el administrador. Por eso no falla con
> "módulo no encontrado" al elevar.

### Opción B — Manual

```bash
python -m venv venv
# Windows:   venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```

Luego arranca usando **el Python del venv por su ruta** (no el del sistema),
para que los paquetes sigan visibles al elevar a administrador:

```bash
# Windows (se auto-eleva a Administrador):
venv\Scripts\python.exe app.py

# macOS / Linux:
sudo venv/bin/python app.py
```

nmap se instala aparte (ver requisitos). `app.py` se auto-eleva: si no tiene
privilegios, relanza pidiendo UAC (Windows) o `sudo` (macOS/Linux) usando ese
mismo intérprete del venv.

En ambos casos, abre **http://127.0.0.1:5000** en el navegador.

### Autodetección del sistema

Al arrancar, NetScope reconoce el sistema y muestra una barra de estado con lo
que tiene y lo que le falta (permisos, captura, nmap). Si algo falta, te da el
comando exacto para instalarlo en tu SO.

### Nota para Windows

Instala Python desde [python.org](https://www.python.org/downloads/) (opción
*"Add python.exe to PATH"*), **no** desde la Microsoft Store: la versión de la
Store queda aislada por usuario y el proceso elevado a Administrador puede no
verla.

## Cómo funciona

### Descubrimiento e identificación
Hace un **ARP scan** del segmento de red para encontrar todo lo conectado, y
luego resuelve el nombre de cada equipo por orden: mDNS/Bonjour → DNS inverso →
NetBIOS → fabricante por MAC.

> Muchos teléfonos usan MAC aleatoria y no publican nombre; en esos casos verás
> `fabricante + IP`. Es privacidad del dispositivo, no un fallo.

### Escaneo profundo (`nmap`)
El botón **[ scan ]** de cada equipo lanza un análisis con nmap bajo demanda:
sistema operativo estimado, puertos abiertos y el servicio/versión de cada uno.
Es por equipo (no toda la red de golpe) porque es un escaneo pesado.

### Interfaz (multipágina, estilo GitHub)
La app ya no vive en un solo `index.html`: cada sección tiene su propia ruta
(`/` resumen, `/devices` árbol, `/traffic` tráfico, `/device/<ip>` detalle,
`/system` estado), con una barra lateral tipo GitHub, tema claro/oscuro y la
fuente **SF Pro**.

### Log de conexiones y enlaces
En la página de cada dispositivo hay un **log en vivo** de a dónde habla, que no
parpadea (va agregando líneas) y tiene botón **Limpiar**. Captura desde tres
fuentes:

- **DNS** — dominios que el equipo resuelve.
- **SNI** — nombre del servidor en el handshake TLS (más fiable que DNS).
- **HTTP** — URL completa, solo para el poco tráfico sin cifrar.

> **Límite real:** con **HTTPS la ruta (`/loquesea`) va cifrada** y no se puede
> ver; lo máximo es el dominio. La URL completa solo aparece en tráfico HTTP
> plano. Es un límite criptográfico, no del programa.

### Intercepción (`[ inspect ]`)
En una Wi-Fi normal tu equipo solo ve su propio tráfico. Para ver **todo** el de
otro equipo, NetScope lo intercepta con **ARP spoofing selectivo** (solo el que
elijas):

- Activa el **reenvío de IP** para **no cortarle internet** al equipo.
- Se **revierte solo** al desactivarlo o cerrar el programa (la red queda sana).
- **HTTPS sigue cifrado**: ves *a dónde* habla cada equipo (IPs y dominios) y
  cuánto tráfico mueve, **no el contenido** de lo que envía.

Alternativa sin intercepción: si tu router admite **OpenWRT**, capturar ahí con
`tcpdump` da visibilidad total sin spoofing.

---

## Estructura del proyecto

```
netscope/
├── run.py              # instalador + lanzador (dependencias, nmap, privilegios)
├── app.py              # servidor (waitress) : rutas de páginas + API
├── scanner.py          # descubrimiento de dispositivos (ARP) + nombres en paralelo
├── sniffer.py          # captura + log (DNS / SNI / HTTP), optimizado
├── mitm.py             # intercepción selectiva (ARP spoofing)
├── deepscan.py         # wrapper de nmap (SO, puertos, servicios)
├── wifi.py             # info de la red Wi-Fi (SSID, señal, canal)
├── speedtest.py        # test de velocidad (latencia / descarga / subida)
├── storage.py          # base de datos local (SQLite): equipos, eventos, ajustes
├── notify.py           # notificaciones por Telegram (opcional)
├── platform_setup.py   # detección de SO, permisos, dependencias y elevación
├── requirements.txt
├── static/
│   ├── css/app.css
│   ├── img/logo-mark.png
│   └── js/             # common, overview, devices, traffic, device, speed, history, settings, system
└── templates/
    ├── base.html       # topbar (logo) + barra lateral
    └── overview · devices · traffic · speed · device · history · settings · system (.html)
```

## Distribución (ejecutable clicable)

Para no instalar Python en cada máquina:

```bash
pip install pyinstaller
pyinstaller --onefile --add-data "templates:templates" app.py
```

En **Windows** el separador es `;` → `--add-data "templates;templates"`.
El binario queda en `dist/` (igual necesita admin + Npcap/nmap).

---

## Roadmap

- [ ] Historial en SQLite y alerta cuando aparece un equipo desconocido
- [ ] Bloquear un equipo desde la consola (cortarle el acceso)
- [ ] Gráfica temporal del tráfico
- [ ] Resolución inversa de las IPs externas a las que habla cada equipo

## Licencia

Elige una licencia para tu repo (por ejemplo MIT) y añádela como archivo
`LICENSE`. Sin licencia, por defecto nadie puede reutilizar el código.
