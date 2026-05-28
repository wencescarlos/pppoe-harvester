#!/usr/bin/env python3
"""
pppoe-harvester
===============
Herramienta para extraer credenciales PPPoE de routers FTTH españoles
actuando como servidor PPPoE temporal y capturando el handshake de
autenticación PAP.

Útil cuando se sustituye el router del operador por firmware propio
(pfSense, OpenWrt, OPNsense…) y el ISP se niega a facilitar las
credenciales PPPoE.

Requisitos
----------
    pip install netifaces
    apt install tshark ppp pppoeconf ppp-dev build-essential

Uso
---
    sudo python3 pppoe_harvester.py
    sudo python3 pppoe_harvester.py --isp movistar
    sudo python3 pppoe_harvester.py --vlan 20 --interfaz eth0
    sudo python3 pppoe_harvester.py --listar-isps

Autor  : wencescarlos (github.com/wencescarlos)
Licencia: MIT
"""

from __future__ import annotations

import argparse
import datetime
import itertools
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import netifaces


# ── Constantes ────────────────────────────────────────────────────────────────

NOMBRE_APP  = "pppoe-harvester"
VERSION_APP = "1.0.0"

REPO_RAW_URL = "https://raw.githubusercontent.com/wencescarlos/pppoe-harvester/main/pppoe_harvester.py"

DIR_TRABAJO     = Path.home() / NOMBRE_APP
ARCHIVO_LOG     = DIR_TRABAJO / f"{NOMBRE_APP}.log"
ARCHIVO_CAPTURA = DIR_TRABAJO / "captura.txt"
PPP_OPCIONES    = Path("/etc/ppp/options")
PAP_SECRETOS    = Path("/etc/ppp/pap-secrets")
URL_RP_PPPOE    = "https://salsa.debian.org/dskoll/rp-pppoe/-/archive/master/rp-pppoe-master.tar.gz"
IP_SERVIDOR_PPP = "10.0.0.1/16"
HOST_PING       = "8.8.8.8"
FRAMES_RELOJ    = ("🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚", "🕛")

CONTENIDO_PPP_OPCIONES = """\
ms-dns 8.8.8.8
asyncmap 0
noauth
crtscts
lock
hide-password
modem
proxyarp
lcp-echo-interval 10
lcp-echo-failure 2
noipx
plugin /etc/ppp/plugins/rp-pppoe.so
require-pap
ktune
nobsdcomp
noccp
novj
"""

LINEA_PAP_TEMPORAL = '"UsuarioTemporal"\t*\t"ContrasenyaTemporal"\t*\n'

# Operadores españoles y su VLAN FTTH
OPERADORES_VLAN: dict[str, tuple[str, int]] = {
    "digi":       ("DiGi",                          20),
    "movistar":   ("Movistar / Tuenti / O2",          6),
    "vodafone":   ("Vodafone / Lowi",               100),
    "neba":       ("NEBA Vodafone / Lowi",            24),
    "jazztel":    ("Jazztel",                       1074),
    "masmovil":   ("MásMóvil / PepePhone / Yoigo",   20),
    "orange":     ("Orange / Amena",                832),
    "adamo":      ("Adamo",                         603),
}


# ── Colores de terminal (sin dependencias externas) ───────────────────────────

class C:
    """Códigos ANSI de color y formato para la terminal."""
    RESET   = "\033[0m"
    NEGRITA = "\033[1m"
    VERDE   = "\033[92m"
    AMARILLO= "\033[93m"
    CIAN    = "\033[96m"
    MAGENTA = "\033[95m"
    GRIS    = "\033[90m"
    BLANCO  = "\033[1m\033[97m"
    ROJO    = "\033[91m"
    BORRAR  = "\033[K"
    ARRIBA  = "\033[1A"

    @staticmethod
    def ok(msg: str) -> str:
        return f"{C.VERDE}{C.BORRAR}  ✔  {msg}{C.RESET}"

    @staticmethod
    def info(msg: str) -> str:
        return f"{C.CIAN}{C.BORRAR}  →  {msg}{C.RESET}"

    @staticmethod
    def aviso(msg: str) -> str:
        return f"{C.AMARILLO}{C.BORRAR}  ⚠  {msg}{C.RESET}"

    @staticmethod
    def error(msg: str) -> str:
        return f"{C.ROJO}{C.BORRAR}  ✖  {msg}{C.RESET}"

    @staticmethod
    def resaltar(msg: str) -> str:
        return f"{C.BLANCO}{msg}{C.RESET}"

    @staticmethod
    def banner(titulo: str) -> str:
        barra = "─" * (len(titulo) + 4)
        return (
            f"{C.AMARILLO}┌{barra}┐\n"
            f"│  {C.BLANCO}{titulo}{C.AMARILLO}  │\n"
            f"└{barra}┘{C.RESET}"
        )


# ── Configuración del registro (log) ──────────────────────────────────────────

def configurar_log(detallado: bool = False) -> logging.Logger:
    """Devuelve un logger que escribe en archivo y opcionalmente en stderr."""
    DIR_TRABAJO.mkdir(parents=True, exist_ok=True)

    formato  = "%(asctime)s  %(levelname)-8s  %(message)s"
    fecha_fmt = "%d/%m/%Y %H:%M:%S"
    nivel    = logging.DEBUG if detallado else logging.INFO

    manejador_archivo = logging.FileHandler(ARCHIVO_LOG, encoding="utf-8")
    manejador_archivo.setFormatter(logging.Formatter(formato, fecha_fmt))
    manejador_archivo.setLevel(logging.DEBUG)

    logger = logging.getLogger(NOMBRE_APP)
    logger.setLevel(nivel)
    logger.addHandler(manejador_archivo)

    if detallado:
        manejador_consola = logging.StreamHandler()
        manejador_consola.setFormatter(logging.Formatter(formato, fecha_fmt))
        logger.addHandler(manejador_consola)

    return logger


# ── Tipos de datos ─────────────────────────────────────────────────────────────

@dataclass
class CredencialesPPPoE:
    usuario:   str
    contrasena: str
    transcurrido: datetime.timedelta

    def __str__(self) -> str:
        segs = int(self.transcurrido.total_seconds())
        m, s = divmod(segs, 60)
        tiempo_str = f"{m}m {s}s" if m else f"{s}s"
        return (
            f"\n{C.AMARILLO}{'─'*42}\n"
            f"{C.BLANCO}  ¡Credenciales PPPoE encontradas!\n"
            f"{C.VERDE}  Usuario    : {C.BLANCO}{self.usuario}\n"
            f"{C.VERDE}  Contraseña : {C.BLANCO}{self.contrasena}\n"
            f"{C.GRIS}  Tiempo     : {tiempo_str}\n"
            f"{C.AMARILLO}{'─'*42}{C.RESET}\n"
        )


# ── Utilidades de red ─────────────────────────────────────────────────────────

def requerir_root() -> None:
    """Relanza el script con sudo si no se ejecuta como root."""
    if os.geteuid() != 0:
        print(C.aviso("Se requieren privilegios de superusuario — relanzando con sudo…"))
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


def detectar_interfaz_ethernet() -> str:
    """Devuelve la primera interfaz Ethernet encontrada (eth* o en*)."""
    for interfaz in netifaces.interfaces():
        if interfaz.startswith(("eth", "en")):
            return interfaz
    raise RuntimeError("No se ha detectado ninguna interfaz Ethernet.")


def eliminar_interfaces_vlan() -> None:
    """Elimina todas las interfaces virtuales con notación de punto (p.ej. eth0.20)."""
    for interfaz in netifaces.interfaces():
        if "." in interfaz:
            subprocess.run(
                ["ip", "link", "delete", interfaz],
                check=False, capture_output=True
            )


def crear_interfaz_vlan(padre: str, id_vlan: int) -> str:
    """Crea una subinterfaz VLAN y la levanta. Devuelve su nombre."""
    nombre = f"pppoe.{id_vlan}"
    subprocess.run(
        ["ip", "link", "add", "link", padre, "name", nombre,
         "type", "vlan", "id", str(id_vlan)],
        check=True, capture_output=True
    )
    subprocess.run(["ip", "addr", "flush", "dev", nombre],              check=True, capture_output=True)
    subprocess.run(["ip", "addr", "add", IP_SERVIDOR_PPP, "dev", nombre], check=True, capture_output=True)
    subprocess.run(["ip", "link", "set", nombre, "up"],                  check=True, capture_output=True)
    return nombre


def esperar_internet(host: str = HOST_PING, logger: Optional[logging.Logger] = None) -> None:
    """Bloquea hasta que un ping a *host* tenga éxito."""
    inicio  = datetime.datetime.now()
    spinner = itertools.cycle(FRAMES_RELOJ)
    while True:
        try:
            subprocess.check_output(
                ["ping", "-c", "2", "-W", "3", host],
                stderr=subprocess.DEVNULL
            )
            return
        except subprocess.CalledProcessError:
            transcurrido = (datetime.datetime.now() - inicio).seconds
            m, s = divmod(transcurrido, 60)
            ts = f"{m:02d}:{s:02d}" if m else f"{s:2d}s"
            print(
                f"\r{C.BORRAR}  {next(spinner)}  "
                f"{C.AMARILLO}Esperando conexión a internet…  "
                f"{C.BLANCO}{ts}{C.RESET}",
                end="", flush=True
            )
            if logger:
                logger.debug("Esperando conectividad a internet…")
            time.sleep(1)


def terminar_procesos(*nombres: str) -> None:
    """Envía señal de terminación a los procesos indicados y espera su cierre."""
    for nombre in nombres:
        subprocess.run(["killall", "-q", "-w", nombre], check=False, capture_output=True)


# ── Instalación de dependencias ───────────────────────────────────────────────

def _apt_instalar(*paquetes: str) -> None:
    entorno = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    subprocess.run(
        ["apt-get", "install", "-y", *paquetes],
        check=True, capture_output=True, env=entorno
    )


def _esta_instalado(binario: str) -> bool:
    return shutil.which(binario) is not None


def asegurar_repositorio_universe(logger: logging.Logger) -> None:
    """Añade el repositorio 'universe' de APT si no está presente."""
    fuentes = Path("/etc/apt/sources.list").read_text(encoding="utf-8")
    if "universe" not in fuentes:
        print(C.info('Añadiendo repositorio "universe"…'))
        esperar_internet(logger=logger)
        subprocess.run(
            ["add-apt-repository", "-y", "universe"],
            check=True, capture_output=True
        )
        logger.info('Repositorio "universe" añadido.')
    else:
        logger.debug('El repositorio "universe" ya estaba presente.')


def instalar_tshark(logger: logging.Logger) -> None:
    """Instala tshark si no está disponible en el sistema."""
    if _esta_instalado("tshark"):
        print(C.ok("tshark ya estaba instalado"))
        logger.debug("tshark ya estaba instalado.")
        return

    print(C.info("Instalando tshark…"))
    logger.info("Instalando tshark.")
    cmd_debconf = (
        'echo "wireshark-common wireshark-common/install-setuid boolean true" '
        "| debconf-set-selections"
    )
    subprocess.run(cmd_debconf, shell=True, check=False, capture_output=True)
    _apt_instalar("tshark")
    logger.info("tshark instalado correctamente.")
    print(C.ok("tshark instalado"))


def instalar_rp_pppoe(logger: logging.Logger) -> None:
    """Compila e instala RP-PPPoE desde fuentes si pppoe-server no está presente."""
    if _esta_instalado("pppoe-server"):
        print(C.ok("pppoe-server ya estaba instalado"))
        logger.debug("pppoe-server ya estaba instalado.")
        return

    print(C.info("Instalando dependencias de RP-PPPoE…"))
    logger.info("Instalando ppp, ppp-dev, pppoeconf, build-essential.")
    _apt_instalar("ppp", "ppp-dev", "pppoeconf", "build-essential")

    ruta_archivo = DIR_TRABAJO / "rp-pppoe-master.tar.gz"
    dir_fuentes  = DIR_TRABAJO / "rp-pppoe-master" / "src"

    print(C.info(f"Descargando RP-PPPoE desde {URL_RP_PPPOE}…"))
    logger.info("Descargando código fuente de RP-PPPoE.")
    urllib.request.urlretrieve(URL_RP_PPPOE, ruta_archivo)

    if not dir_fuentes.exists():
        print(C.info("Descomprimiendo archivo…"))
        with tarfile.open(ruta_archivo, "r:gz") as tar:
            tar.extractall(DIR_TRABAJO)

    dir_original = Path.cwd()
    os.chdir(dir_fuentes)
    try:
        print(C.info("Configurando RP-PPPoE…"))
        subprocess.run(["./configure", "--enable-plugin"], check=True, capture_output=True)
        print(C.info("Compilando RP-PPPoE…"))
        subprocess.run(["make"],                check=True, capture_output=True)
        subprocess.run(["make", "rp-pppoe.so"], check=True, capture_output=True)
        print(C.info("Instalando RP-PPPoE…"))
        subprocess.run(["make", "install"],     check=True, capture_output=True)
        logger.info("RP-PPPoE compilado e instalado correctamente.")
        print(C.ok("RP-PPPoE instalado"))
    finally:
        os.chdir(dir_original)


def configurar_servidor_ppp(logger: logging.Logger) -> None:
    """Escribe /etc/ppp/options y añade una entrada temporal a pap-secrets."""
    PPP_OPCIONES.write_text(CONTENIDO_PPP_OPCIONES, encoding="utf-8")
    logger.info("Archivo de opciones PPP escrito.")

    secretos = PAP_SECRETOS.read_text(encoding="utf-8")
    if LINEA_PAP_TEMPORAL not in secretos:
        with PAP_SECRETOS.open("a", encoding="utf-8") as f:
            f.write(LINEA_PAP_TEMPORAL)
        logger.info("Credenciales temporales añadidas a pap-secrets.")


# ── Captura y extracción de credenciales ──────────────────────────────────────

_RE_USUARIO = re.compile(r"Peer-ID='([\w@.\-/\\]*)'")
_RE_CLAVE   = re.compile(r"Password='([\w@.\-/\\]*)'")


def _extraer_credenciales(linea: str) -> tuple[str, str]:
    """Extrae (usuario, contraseña) de una línea PAP de tshark, o ('', '')."""
    if "Authenticate-Request" not in linea:
        return "", ""
    m_usuario = _RE_USUARIO.search(linea)
    m_clave   = _RE_CLAVE.search(linea)
    usuario = m_usuario.group(1) if m_usuario else ""
    clave   = m_clave.group(1)   if m_clave   else ""
    return usuario, clave


def capturar_credenciales(
    interfaz_vlan: str,
    logger: logging.Logger,
) -> CredencialesPPPoE:
    """
    Lanza pppoe-server y tshark, luego analiza el archivo de captura hasta
    encontrar credenciales PAP. Devuelve una instancia de CredencialesPPPoE.
    """
    ARCHIVO_CAPTURA.unlink(missing_ok=True)

    logger.info("Iniciando pppoe-server en %s.", interfaz_vlan)
    proceso_pppoe = subprocess.Popen(
        ["pppoe-server", "-C", "ftth", "-I", interfaz_vlan, "-N", "256",
         "-O", str(PPP_OPCIONES)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    logger.info("Iniciando captura con tshark en %s.", interfaz_vlan)
    with ARCHIVO_CAPTURA.open("wb") as salida_captura:
        proceso_tshark = subprocess.Popen(
            ["tshark", "-i", interfaz_vlan, "-T", "text"],
            stdout=salida_captura,
            stderr=subprocess.DEVNULL,
        )

    inicio  = datetime.datetime.now()
    spinner = itertools.cycle(FRAMES_RELOJ)

    print(C.aviso("Puedes detener el proceso en cualquier momento pulsando Ctrl+C.\n"))

    try:
        while True:
            transcurrido = datetime.datetime.now() - inicio
            m, s = divmod(int(transcurrido.total_seconds()), 60)
            ts = f"{m:02d}:{s:02d}" if m else f" {s:2d}s "
            print(
                f"\r{C.BORRAR}  {next(spinner)}  "
                f"{C.AMARILLO}Buscando handshake PPPoE…  "
                f"{C.BLANCO}{ts}{C.RESET}",
                end="", flush=True
            )

            try:
                texto = ARCHIVO_CAPTURA.read_text(encoding="utf-8", errors="replace")
            except OSError:
                time.sleep(0.1)
                continue

            for linea in texto.splitlines():
                usuario, clave = _extraer_credenciales(linea)
                if usuario and clave:
                    logger.info("Credenciales capturadas: usuario=%s", usuario)
                    _registrar_paquetes_capturados(logger)
                    return CredencialesPPPoE(
                        usuario=usuario,
                        contrasena=clave,
                        transcurrido=datetime.datetime.now() - inicio,
                    )

            time.sleep(1 / len(FRAMES_RELOJ))

    except KeyboardInterrupt:
        print(f"\n{C.aviso('Proceso interrumpido por el usuario.')}\n")
        logger.info("Proceso interrumpido por el usuario.")
        _registrar_paquetes_capturados(logger)
        _mostrar_log()
        sys.exit(0)
    finally:
        proceso_pppoe.terminate()
        proceso_tshark.terminate()
        terminar_procesos("tshark", "pppoe-server")


def _registrar_paquetes_capturados(logger: logging.Logger) -> None:
    """Anota en el log el número total de paquetes capturados."""
    try:
        lineas = ARCHIVO_CAPTURA.read_text(encoding="utf-8", errors="replace").splitlines()
        logger.info("Total de paquetes capturados: %d", len(lineas))
    except OSError:
        pass


def _mostrar_log() -> None:
    """Imprime el contenido del archivo de log en la terminal."""
    if ARCHIVO_LOG.exists():
        print(f"\n{C.CIAN}── Registro de sesión ───────────────────{C.RESET}")
        for linea in ARCHIVO_LOG.read_text(encoding="utf-8").splitlines():
            if linea.strip():
                print(f"  {C.MAGENTA}{linea}{C.RESET}")
        print(f"{C.CIAN}─────────────────────────────────────────{C.RESET}\n")


# ── Selección de operador / VLAN ──────────────────────────────────────────────

def seleccionar_vlan_interactivo() -> int:
    """Muestra el menú de operadoras y devuelve el ID de VLAN elegido."""
    operadores = list(OPERADORES_VLAN.items())
    print(f"\n{C.CIAN}Operadoras disponibles:{C.RESET}")
    print(f"{C.AMARILLO}{'─'*42}{C.RESET}")

    for idx, (clave, (nombre, vlan)) in enumerate(operadores, start=1):
        print(f"  {C.BLANCO}[{idx:2d}]  {C.AMARILLO}{nombre:<38}{C.GRIS}VLAN {vlan}{C.RESET}")

    idx_manual = len(operadores) + 1
    print(f"  {C.BLANCO}[{idx_manual:2d}]  {C.AMARILLO}Introducir VLAN manualmente{C.RESET}")
    print()

    while True:
        try:
            opcion = int(input(f"{C.CIAN}Selecciona tu operadora: {C.BLANCO}"))
        except KeyboardInterrupt:
            print()
            sys.exit(0)
        except ValueError:
            print(C.error("Introduce un número válido."))
            continue

        if opcion == idx_manual:
            return _pedir_vlan_manual()
        if 1 <= opcion <= len(operadores):
            return operadores[opcion - 1][1][1]

        print(C.error(f"La opción debe estar entre 1 y {idx_manual}."))


def _pedir_vlan_manual() -> int:
    """Solicita al usuario un ID de VLAN numérico entre 1 y 4094."""
    while True:
        try:
            vlan = int(input(f"{C.CIAN}Introduce el ID de VLAN: {C.BLANCO}"))
            if 1 <= vlan <= 4094:
                return vlan
            print(C.error("La VLAN debe estar entre 1 y 4094."))
        except KeyboardInterrupt:
            print()
            sys.exit(0)
        except ValueError:
            print(C.error("Introduce un número entero válido."))


# ── Interfaz de línea de comandos ─────────────────────────────────────────────

def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=NOMBRE_APP,
        description=(
            "Extrae credenciales PPPoE de un router FTTH español actuando\n"
            "como servidor PPPoE temporal y capturando el handshake de\n"
            "autenticación PAP con tshark."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            f"  sudo python3 {NOMBRE_APP}.py\n"
            f"  sudo python3 {NOMBRE_APP}.py --isp movistar\n"
            f"  sudo python3 {NOMBRE_APP}.py --vlan 20 --interfaz eth0\n"
        ),
    )
    parser.add_argument(
        "--isp",
        choices=list(OPERADORES_VLAN.keys()),
        metavar="OPERADORA",
        help=f"Clave de la operadora ({', '.join(OPERADORES_VLAN.keys())}). Omite el menú interactivo.",
    )
    parser.add_argument(
        "--vlan",
        type=int,
        metavar="ID",
        help="ID de VLAN (1–4094). Tiene prioridad sobre --isp.",
    )
    parser.add_argument(
        "--interfaz",
        metavar="INTERFAZ",
        help="Interfaz Ethernet a usar (se detecta automáticamente si se omite).",
    )
    parser.add_argument(
        "--listar-isps",
        action="store_true",
        help="Muestra la lista de operadoras soportadas y sale.",
    )
    parser.add_argument(
        "--sin-instalacion",
        action="store_true",
        help="Omite las comprobaciones de instalación de dependencias.",
    )
    parser.add_argument(
        "--detallado", "-v",
        action="store_true",
        help="Muestra el log de depuración también en la consola.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION_APP}",
    )
    return parser


def mostrar_lista_operadoras() -> None:
    """Imprime la tabla de operadoras soportadas con su VLAN."""
    print(f"\n{C.CIAN}{NOMBRE_APP} — Operadoras soportadas{C.RESET}")
    print(f"{C.AMARILLO}{'─'*50}{C.RESET}")
    for clave, (nombre, vlan) in OPERADORES_VLAN.items():
        print(f"  {C.BLANCO}{clave:<12}{C.AMARILLO}{nombre:<35}{C.GRIS}VLAN {vlan}{C.RESET}")
    print()


# ── Auto-actualización ────────────────────────────────────────────────────────

def _version_a_tupla(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.strip().split("."))


def auto_actualizar() -> None:
    """Descarga la última versión del repositorio y reemplaza este script si hay actualización."""
    print(C.info("Buscando actualizaciones…"))

    resultado: list[str] = []
    error: list[bool] = []

    def _fetch() -> None:
        try:
            with urllib.request.urlopen(REPO_RAW_URL, timeout=4) as resp:
                resultado.append(resp.read().decode("utf-8"))
        except Exception:
            error.append(True)

    hilo = threading.Thread(target=_fetch, daemon=True)
    hilo.start()
    hilo.join(timeout=5)

    if error or not resultado:
        print(C.aviso("Sin conexión — omitiendo actualización."))
        return

    nuevo_codigo = resultado[0]

    m = re.search(r'^VERSION_APP\s*=\s*["\'](.+?)["\']', nuevo_codigo, re.MULTILINE)
    if not m:
        return

    version_remota = m.group(1)
    if _version_a_tupla(version_remota) <= _version_a_tupla(VERSION_APP):
        print(C.ok(f"Ya tienes la versión más reciente ({VERSION_APP})."))
        return

    ruta_script = Path(__file__).resolve()
    ruta_script.write_text(nuevo_codigo, encoding="utf-8")
    print(C.ok(f"Actualizado a v{version_remota}. Relanzando…"))
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ── Punto de entrada ──────────────────────────────────────────────────────────

def main() -> None:
    parser = construir_parser()
    args   = parser.parse_args()

    if args.listar_isps:
        mostrar_lista_operadoras()
        sys.exit(0)

    auto_actualizar()
    requerir_root()

    os.system("clear")
    print(C.banner(f"{NOMBRE_APP}  v{VERSION_APP}"))
    print()

    logger = configurar_log(detallado=args.detallado)
    logger.info("=== %s v%s iniciado ===", NOMBRE_APP, VERSION_APP)

    terminar_procesos("tshark", "pppoe-server")

    # ── Resolver interfaz ────────────────────────────────────────────────────
    interfaz = args.interfaz
    if interfaz is None:
        try:
            interfaz = detectar_interfaz_ethernet()
            print(C.ok(f"Interfaz Ethernet detectada: {C.resaltar(interfaz)}"))
            logger.info("Interfaz Ethernet: %s", interfaz)
        except RuntimeError as exc:
            print(C.error(str(exc)))
            logger.error(str(exc))
            sys.exit(1)
    else:
        print(C.info(f"Usando interfaz: {C.resaltar(interfaz)}"))
        logger.info("Interfaz especificada por el usuario: %s", interfaz)

    # ── Resolver VLAN ────────────────────────────────────────────────────────
    if args.vlan:
        id_vlan = args.vlan
        logger.info("VLAN especificada por el usuario: %d", id_vlan)
    elif args.isp:
        id_vlan = OPERADORES_VLAN[args.isp][1]
        logger.info("Operadora '%s' seleccionada → VLAN %d", args.isp, id_vlan)
    else:
        id_vlan = seleccionar_vlan_interactivo()
        logger.info("VLAN seleccionada de forma interactiva: %d", id_vlan)

    print(C.info(f"VLAN seleccionada: {C.resaltar(str(id_vlan))}"))

    # ── Instalar dependencias ────────────────────────────────────────────────
    if not args.sin_instalacion:
        print()
        try:
            asegurar_repositorio_universe(logger)
            instalar_tshark(logger)
            instalar_rp_pppoe(logger)
            configurar_servidor_ppp(logger)
        except subprocess.CalledProcessError as exc:
            print(C.error(f"Error durante la instalación de dependencias: {exc}"))
            logger.error("Error de instalación: %s", exc)
            sys.exit(1)

    # ── Configurar interfaz VLAN ─────────────────────────────────────────────
    print()
    print(C.info("Eliminando interfaces virtuales existentes…"))
    eliminar_interfaces_vlan()
    logger.info("Interfaces VLAN anteriores eliminadas.")

    print(C.info(f"Creando interfaz VLAN {id_vlan}…"))
    try:
        interfaz_vlan = crear_interfaz_vlan(interfaz, id_vlan)
        print(C.ok(f"Interfaz {C.resaltar(interfaz_vlan)} lista"))
        logger.info("Interfaz VLAN creada: %s", interfaz_vlan)
    except subprocess.CalledProcessError as exc:
        print(C.error(f"No se pudo crear la interfaz VLAN: {exc}"))
        logger.error("Error al crear la interfaz VLAN: %s", exc)
        sys.exit(1)

    # ── Instrucciones al usuario ─────────────────────────────────────────────
    print()
    print(f"  {C.CIAN}Todo está listo. A partir de este momento no es necesaria")
    print(f"  conexión a internet — puedes desconectar el cable de WAN si lo necesitas.")
    print()
    print(f"  {C.BLANCO}➜  Conecta un cable Ethernet desde este equipo")
    print(f"     al puerto WAN del router y enciéndelo.")
    print(f"{C.RESET}")
    try:
        input(f"  {C.AMARILLO}Pulsa ENTER cuando estés listo… {C.RESET}")
    except KeyboardInterrupt:
        print()
        sys.exit(0)

    terminar_procesos("tshark", "pppoe-server")

    # ── Captura ──────────────────────────────────────────────────────────────
    print()
    credenciales = capturar_credenciales(interfaz_vlan, logger)

    print(credenciales)
    logger.info(
        "Finalizado — usuario: %s | tiempo: %s",
        credenciales.usuario,
        credenciales.transcurrido,
    )


if __name__ == "__main__":
    main()
