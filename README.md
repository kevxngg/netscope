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
| **Inventario de dispositivos** | Busca, filtra y ordena equipos conectados o ausentes; muestra tipo estimado, tráfico, confianza y última vez visto. |
| **Nombres reales** | Combina mDNS/Bonjour, DNS inverso, NetBIOS y fabricante (OUI) para identificar cada equipo. |
| **Escaneo profundo** | Con `nmap`: sistema operativo, puertos abiertos y servicio/versión de cada equipo. |
| **Tráfico por dispositivo** | Bytes y paquetes en vivo, con barras de subida y bajada. |
| **Gráfica de tráfico** | Curva suavizada con escala vertical en MB/s y lecturas cada 0,5 segundos. |
| **Intercepción selectiva** | Ver todo el tráfico de un equipo elegido y a qué dominios habla. |
| **Autodetección del sistema** | Reconoce el SO al arrancar y avisa de permisos y dependencias que falten. |
| **Info Wi-Fi** | Nombre de red (SSID), señal, canal y banda de la red a la que estás conectado. |
| **Test de velocidad** | Latencia, descarga y subida con progreso, cancelación, jitter e historial local de mediciones. |
| **Historial** | Registro local de eventos, bloqueos y dispositivos nuevos. |
| **Nombres personalizados** | Renombra un equipo (ej. "Celular de Kevin"); se guarda en SQLite. |
| **Bloquear equipos** | Corta el acceso a internet de un equipo desde la consola (ARP). |
| **Exportar** | Descarga dispositivos y logs en CSV. |
| **Gráfica en vivo** | Tráfico total de la red en una línea de tiempo. |
| **Detalle de dispositivo** | Ficha de identidad, presencia, tráfico, historial y log filtrable por DNS, SNI y HTTP. |

---

## Requisitos

- **Python 3.8+**
- Permisos de **administrador / root** (el escaneo y la captura los necesitan; NetScope los pide solo)
- **Npcap** — necesario en Windows para ARP y captura de paquetes.
- **nmap** — opcional; necesario únicamente para el escaneo profundo.
- En Windows, los detalles avanzados de Wi-Fi pueden requerir permisos de
  administrador y tener activada la ubicación del sistema.

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

El instalador también comprueba que el entorno virtual tenga `pip`. Si el venv
existe pero está incompleto, intenta repararlo con `ensurepip` y se detiene si
la instalación de dependencias falla, en lugar de abrir una aplicación rota.

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

También puedes ejecutar el diagnóstico sin iniciar la web:

```bash
python diagnostico.py
```

El diagnóstico revisa permisos, dependencias, Npcap, nmap, interfaces, gateway
y realiza una prueba ARP usando la interfaz de red seleccionada por NetScope.

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

Cuando hay varias interfaces, primero elige la red que contiene el gateway y
descarta adaptadores virtuales como WSL, VPN, Docker o Bluetooth. El ARP se
envía por la interfaz seleccionada, evitando que un adaptador virtual devuelva
una lista vacía.

> Muchos teléfonos usan MAC aleatoria y no publican nombre; en esos casos verás
> `fabricante + IP`. Es privacidad del dispositivo, no un fallo.

### Escaneo profundo (`nmap`)
El botón **[ scan ]** de cada equipo lanza un análisis con nmap bajo demanda:
sistema operativo estimado, puertos abiertos y el servicio/versión de cada uno.
Es por equipo (no toda la red de golpe) porque es un escaneo pesado.

### Inventario y clasificación
La página **Dispositivos** combina los equipos detectados con el historial local.
Permite buscar por nombre, IP, MAC o fabricante, filtrar por estado y ordenar
por IP, nombre, tráfico, última conexión o fabricante. El tipo se estima de
forma conservadora usando nombres y fabricantes conocidos: cámara, celular,
computador, router, impresora, TV/consola u otro dispositivo.

Al abrir un equipo se muestra su identidad, estado, tráfico, veces visto,
historial de eventos y un log filtrable. Las acciones de confianza e inspección
están disponibles desde la ficha y el inventario.

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

La página de tráfico refresca los contadores aproximadamente cada 0,5 segundos
sin acumular peticiones. La gráfica usa una curva suavizada y una escala
vertical en MB/s. La lista muestra los dispositivos descubiertos en la red
local, no cada IP externa como si fuera un dispositivo.

En el resumen, el proveedor, ASN, país y ciudad son datos aproximados de la IP
pública obtenidos desde un servicio externo. No representan necesariamente la
ubicación física exacta del router o del servidor que estás usando.

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
├── diagnostico.py      # diagnóstico de requisitos, interfaces, gateway y ARP
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

## Estado actual

- [x] Escaneo ARP con selección de interfaz y filtro de adaptadores virtuales.
- [x] Identificación por mDNS, DNS inverso, NetBIOS y fabricante OUI.
- [x] Tráfico en vivo con contadores por dispositivo y gráfica suavizada.
- [x] Escaneo profundo opcional con nmap.
- [x] Historial local, nombres personalizados, confianza y exportación CSV.
- [x] Intercepción y bloqueo selectivos con restauración de tablas ARP.
- [x] Diagnóstico de permisos, dependencias, Npcap, gateway y ARP.
- [x] Clasificación visual de dispositivos y ficha detallada con historial.
- [x] Test de velocidad con progreso, cancelación, jitter e historial local.

## Próximas mejoras

- [ ] Resolver nombres de IP externas en el registro de tráfico.
- [ ] Persistir muestras de tráfico para consultar gráficas históricas.

## Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el archivo
[`LICENSE`](LICENSE) para ver el texto completo.
