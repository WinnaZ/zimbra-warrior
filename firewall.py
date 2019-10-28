# from shutil import which
from distutils.spawn import find_executable as which
import subprocess
from datetime import datetime, timedelta
import re
import abc
import logging

"""Modulo que controla como se utilizara el firewall, 
uso el patron state para resolver si usar iptables o firewald
por que fui a la facultad"""

# Para invocar usar la funcion getFirewall()


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Firewall:
    """
    Interfaz de la api
    mantiene oculta la instancia de FirewallConcreto
    """

    def __init__(self, state):
        self._state = state

    def bloquear(self, ip, tiempo=6):
        self._state.bloquear(ip, tiempo)

    def inicializar(self, tabla="zimbra-block"):
        self._state.inicializar(tabla)

    def finalizar(self, tabla="zimbra-block"):
        self._state.finalizar(tabla)


# class State(metaclass=abc.ABCMeta):
class State:
    """
    Define una interfaz para los determinados comportamientos
    asociados al los estados
    """

    @abc.abstractmethod
    def __init__(self, ruta):
        pass

    @abc.abstractmethod
    def bloquear(self, ip, tiempo=6, tabla="zimbra-block"):
        pass

    @abc.abstractmethod
    def inicializar(self, tabla="zimbra-block"):
        pass

    @abc.abstractmethod
    def finalizar(self, tabla="zimbra-block"):
        pass


class FirewallD(State):
    def bloquear(self, ip, tiempo=6, tabla="zimbra-block"):
        pass


class Iptables(State):
    def __init__(self, ruta):
        self._ruta = ruta
        self._awk = which("awk")

    def _eliminar_entrada(self, ip, tabla="zimbra-block"):
        """Verifica si la ip esta en la tabla y la elimina"""
        awk_code = "{if (NR!=1 &&d NR!=2){print $1, $5}}"
        comando = [self._ruta, "--line", "--numeric", "-L", tabla]
        try:
            iptables_ps = subprocess.Popen(comando, stdout=subprocess.PIPE)
            comando = [self._awk, awk_code]
            awk_ps = subprocess.Popen(
                comando, stdin=iptables_ps.stdout, stdout=subprocess.PIPE
            )
            iptables_ps.stdout.close()
            output = awk_ps.communicate()[0]

            lineas = output.decode("utf-8").split("\n")
            lineas.reverse()
            for linea in lineas:
                if linea:
                    linea = str(linea).split()
                    if linea[1] == ip:
                        comando = [self._ruta, "-D", tabla, linea[0]]
                        subprocess.call(comando)

        except:
            raise OSError(
                "Un error inesperado sucedio al parsear la salida de iptables."
            )

    def bloquear(self, ip, tiempo=6, tabla="zimbra-block"):
        self._eliminar_entrada(ip, tabla)
        fecha_finalizacion = _getTiempoFuturo()
        comando = [
            self._ruta,
            "-I",
            tabla,
            "-s",
            ip,
            "-m",
            "time",
            "--utc",
            "--datestop",
            fecha_finalizacion,
            "-j",
            "DROP",
        ]
        exit_code = subprocess.call(comando)
        if exit_code != 0:
            logger.debug("iptables-bloquear: exit-code: {}".format(exit_code))
            raise ValueError("Ocurrio un error al bloquar la ip {}".format(ip))

    def inicializar(self, tabla="zimbra-block"):
        # Verifico si la chain existe
        comando = [self._ruta, "-L", tabla]
        try:
            subprocess.call(comando, check=True)
        except:
            # No existe la tabla
            # Creo la tabla
            logger.debug("Creando la tabla: {}.".format(tabla))
            comando = [self._ruta, "-N", tabla]
            subprocess.call(comando)
        logger.debug("La Tabla: {} ya existe.".format(tabla))

        # Chequeamos si la chain ya esta apuntada
        comando = [self._ruta, "-C", "INPUT", "-j", tabla]
        try:
            subprocess.call(comando, check=True)
        except:
            # La agrego a la chain de INPUT
            logger.debug("La tabla {} no existe en INPUT.".format(tabla))
            logger.debug("Agregamos la tabla {} a INPUT.".format(tabla))
            comando = [self._ruta, "-A", "INPUT", "-j", tabla]
            subprocess.call(comando)

    def finalizar(self, tabla="zimbra-block"):
        # Borramos las reglas
        comando = [self._ruta, "-F", tabla]
        exit_code = subprocess.call(comando)
        # Borramos la chain
        # comando = [self._ruta, "-X", tabla]
        # exit_code = subprocess.call(comando)


def _getTiempoFuturo(horas=6):
    """Devuelve la fecha actual+ x horas en el formato que le sirve a iptables, devuelve en UTC"""
    return (datetime.utcnow() + timedelta(hours=horas)).strftime("%Y-%m-%dT%H:%M")


def getFirewall():
    "Funcion de ayuda para obtener la clase de firewall"
    # ruta = which("firewall-cmd")
    # if ruta:
    #    return Firewall(FirewallD(ruta))

    ruta = which("awk")
    if not ruta:
        raise OSError("No se encontro el binario de awk.")

    ruta = which("iptables")
    if ruta:
        return Firewall(Iptables(ruta))

    raise OSError("No se encontro firewall-cmd ni iptables.")
