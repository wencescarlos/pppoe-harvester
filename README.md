# pppoe-harvester

Herramienta de línea de comandos para recuperar credenciales PPPoE de routers FTTH españoles.

Funciona actuando temporalmente como servidor PPPoE en el puerto WAN del router,
capturando el handshake de autenticación PAP con `tshark` y extrayendo el usuario
y la contraseña del flujo de paquetes.

Útil cuando quieres sustituir el router de tu operadora por uno propio
(pfSense, OPNsense, OpenWrt…) y el ISP se niega a proporcionarte las
credenciales PPPoE directamente.

> **Probado en:** Ubuntu 22.04 / 24.04 · Debian 12

---

## Operadoras soportadas

| Clave      | Operadora                      | VLAN |
|------------|--------------------------------|------|
| `digi`     | DiGi                           | 20   |
| `movistar` | Movistar / Tuenti / O2         | 6    |
| `vodafone` | Vodafone / Lowi                | 100  |
| `neba`     | NEBA Vodafone / Lowi           | 24   |
| `jazztel`  | Jazztel                        | 1074 |
| `masmovil` | MásMóvil / PepePhone / Yoigo   | 20   |
| `orange`   | Orange / Amena                 | 832  |
| `adamo`    | Adamo                          | 603  |

Cualquier otro ISP puede usarse introduciendo el ID de VLAN manualmente.

---

## Requisitos

- Python 3.9+
- Linux (probado en Debian/Ubuntu)
- Privilegios de superusuario (root)

### Dependencia Python

```bash
pip install netifaces
```

### Dependencias del sistema

El script las instala automáticamente en el primer uso:

- `tshark`
- `ppp`, `ppp-dev`, `pppoeconf`
- `build-essential`
- [RP-PPPoE](https://salsa.debian.org/dskoll/rp-pppoe) (compilado desde fuentes)

---

## Instalación

```bash
git clone https://github.com/wencescarlos/pppoe-harvester.git
cd pppoe-harvester
pip install netifaces
```

---

## Uso

### Modo interactivo (recomendado para la primera ejecución)

```bash
sudo python3 pppoe_harvester.py
```

### Especificar operadora directamente

```bash
sudo python3 pppoe_harvester.py --isp movistar
```

### Especificar VLAN e interfaz manualmente

```bash
sudo python3 pppoe_harvester.py --vlan 20 --interfaz eth0
```

### Listar operadoras soportadas

```bash
python3 pppoe_harvester.py --listar-isps
```

### Omitir instalación de dependencias (si ya están instaladas)

```bash
sudo python3 pppoe_harvester.py --sin-instalacion --isp digi
```

### Todas las opciones

```
uso: pppoe-harvester [-h] [--isp OPERADORA] [--vlan ID] [--interfaz INTERFAZ]
                     [--listar-isps] [--sin-instalacion] [--detallado] [--version]

opciones:
  --isp OPERADORA    Clave de la operadora (omite el menú interactivo)
  --vlan ID          ID de VLAN 1–4094 (tiene prioridad sobre --isp)
  --interfaz IFACE   Interfaz Ethernet (se detecta automáticamente si se omite)
  --listar-isps      Muestra las operadoras soportadas y sale
  --sin-instalacion  Omite las comprobaciones de instalación
  --detallado, -v    Muestra el log de depuración en consola
  --version          Muestra la versión y sale
```

---

## Cómo funciona

1. Detecta (o acepta por argumento) la interfaz Ethernet conectada al puerto WAN del router.
2. Crea una subinterfaz VLAN con el tag del ISP seleccionado.
3. Configura e inicia `pppoe-server` (RP-PPPoE) en esa interfaz.
4. Captura todo el tráfico con `tshark`.
5. Analiza cada paquete buscando un `Authenticate-Request` PAP.
6. Extrae y muestra el usuario y la contraseña.

---

## Ejemplo de salida

```
  ✔  Interfaz Ethernet detectada: eth0
  →  VLAN seleccionada: 6
  ✔  tshark ya estaba instalado
  ✔  pppoe-server ya estaba instalado

  Todo está listo. Conecta un cable Ethernet desde este equipo
  al puerto WAN del router y enciéndelo.

  ➜  Pulsa ENTER cuando estés listo…

  🕓  Buscando handshake PPPoE…   8s

──────────────────────────────────────────
  ¡Credenciales PPPoE encontradas!
  Usuario    : adsl/12345678X@movistar.es
  Contraseña : micontrasena123
  Tiempo     : 8s
──────────────────────────────────────────
```

El log completo de la sesión se guarda en `~/pppoe-harvester/pppoe-harvester.log`.

---

## Notas de seguridad

- Esta herramienta requiere root y modifica `/etc/ppp/options` y `/etc/ppp/pap-secrets`.
- Escribe una entrada **temporal** (`UsuarioTemporal` / `ContrasenyaTemporal`) en `pap-secrets`
  que deberías eliminar tras obtener las credenciales reales.
- Úsala únicamente en tu propio equipo y red.

---

## Licencia

MIT
