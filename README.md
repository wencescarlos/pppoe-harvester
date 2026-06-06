# pppoe-harvester

Recupera tus credenciales PPPoE del router FTTH cuando tu ISP no te las da.

Conecta el puerto WAN del router al puerto Ethernet de tu portátil, ejecuta el script y captura el usuario y contraseña PPPoE automáticamente.

> Probado en Ubuntu 22.04/24.04 y Debian 12. Requiere root.

---

## Cómo funciona

1. Actúa como servidor PPPoE temporal en tu interfaz Ethernet.
2. Crea una subinterfaz VLAN con el tag de tu operadora.
3. Cuando el router arranca e intenta conectarse, captura el handshake PAP con `tshark`.
4. Extrae y muestra el usuario y la contraseña.

---

## Instalación y primera ejecución

Hazlo **con WiFi conectado** (necesitas internet para instalar dependencias):

```bash
git clone https://github.com/wencescarlos/pppoe-harvester.git
cd pppoe-harvester
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/python pppoe_harvester.py
```

El script instala automáticamente `tshark` y `pppoe-server` en el primer uso.

---

## Segunda ejecución (captura real)

Una vez instaladas las dependencias, **desconecta el WiFi** y conecta el cable WAN del router a tu portátil:

```bash
sudo .venv/bin/python pppoe_harvester.py --isp movistar
```

El script **no necesita internet** para capturar. Se actualiza solo desde GitHub si hay conexión disponible, y lo omite silenciosamente si no la hay.

---

## Operadoras soportadas

| Clave        | Operadora                    | VLAN |
|--------------|------------------------------|------|
| `digi`       | DiGi                         | 20   |
| `movistar`   | Movistar / Tuenti / O2       | 6    |
| `vodafone`   | Vodafone / Lowi              | 100  |
| `neba`       | NEBA Vodafone / Lowi         | 24   |
| `jazztel`    | Jazztel                      | 1074 |
| `masmovil`   | MásMóvil / PepePhone / Yoigo | 20   |
| `orange`     | Orange / Amena               | 832  |
| `adamo`      | Adamo                        | 603  |

Para cualquier otro ISP usa `--vlan ID` con el número de VLAN de tu operadora.

---

## Opciones

```
--isp OPERADORA      Selecciona operadora directamente (omite el menú)
--vlan ID            ID de VLAN manual (1–4094), tiene prioridad sobre --isp
--interfaz IFACE     Interfaz Ethernet (se detecta automáticamente)
--listar-isps        Muestra las operadoras soportadas y sale
--sin-instalacion    Omite la instalación de dependencias del sistema
--detallado, -v      Muestra el log de depuración en consola
--version            Muestra la versión
```

---

## Licencia

MIT
