# pppoe-harvester

Recupera tus credenciales PPPoE del router FTTH cuando tu ISP no te las da.

Conecta este equipo al puerto WAN del router, ejecuta el script y captura el usuario y contraseña PPPoE automáticamente.

> Probado en Ubuntu 22.04/24.04 y Debian 12. Requiere root.

---

## Instalación

```bash
git clone https://github.com/wencescarlos/pppoe-harvester.git
cd pppoe-harvester
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Las dependencias del sistema (`tshark`, `pppoe-server`, etc.) se instalan solas en el primer uso.

---

## Uso

```bash
sudo .venv/bin/python pppoe_harvester.py
```

O con tu operadora directamente:

```bash
sudo .venv/bin/python pppoe_harvester.py --isp movistar
```

El script **se actualiza solo** desde este repositorio cada vez que se ejecuta.

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
--isp OPERADORA      Selecciona operadora directamente
--vlan ID            ID de VLAN manual (1–4094)
--interfaz IFACE     Interfaz Ethernet (se detecta automáticamente)
--listar-isps        Muestra las operadoras y sale
--sin-instalacion    Omite la instalación de dependencias
--detallado, -v      Log de depuración en consola
--version            Muestra la versión
```

---

## Licencia

MIT
