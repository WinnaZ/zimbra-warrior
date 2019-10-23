from shutil import which
import subprocess
from datetime import datetime, timedelta
import abc
import logging

"""Modulo que controla como se utilizara el firewall, 
uso el patron state para resolver si usar iptables o firewald
por que fui a la facultad"""

# Para invocar usar la funcion getFirewall()


logger = logging.getLogger(__name__)


class Firewall:
    """
    Interfaz de la api
    mantiene oculta la instancia de FirewallConcreto
    """

    def __init__(self, state):
        self._state = state

    def bloquear(self, ip, tiempo):
        self._sate.bloquear(ip, tiempo)


class State(metaclass=abc.ABCMeta):
    """
    Define una interfaz para los determinados comportamientos
    asociados al los estados
    """

    @abc.abstractmethod
    def __init__(self, ruta):
        _ruta = ruta

    @abc.abstractmethod
    def bloquear(self, ip, tiempo, tabla="zimbra-block"):
        pass

    @abc.abstractmethod
    def inicializar(self, tabla="zimbra-block"):
        pass

    @abc.abstractmethod
    def finalizar(self, tabla="zimbra-block"):
        pass


class FirewallD(State):
    def bloquear(self, ip, tiempo, tabla="zimbra-block"):
        pass


class Iptables(State):
    def bloquear(self, ip, tiempo, tabla="zimbra-block"):
        fecha_finalizacion = _getTiempoFuturo()
        comando = [
            self._ruta,
            "-I",
            tabla,
            "-s",
            ip,
            "-m time",
            "--datestop",
            fecha_finalizacion,
            "-j DROP",
        ]
        stderr = ""
        exit_code = subprocess.call(comando, stderr=stderr)
        if exit_code != 0:
            logger.debug("iptables-bloquear: exit-code: {}".format(exit_code))
            logger.debug("iptables-bloquear: stderr: {}".format(stderr))
            raise ValueError("Ocurrio un error al bloquar la ip {}".format(ip))

    @abc.abstractmethod
    def inicializar(self, tabla="zimbra-block"):
        # Creo la tabla
        comando = [self._ruta, "-N", tabla]
        stderr = ""
        exit_code = subprocess.call(comando, stderr=stderr)
        # en caso de que la tabla ya exista
        if exit_code != 0 and stderr.strip() == "iptables: Chain already exists.":
            logger.debug("La tabla {} ya existe.".format(tabla))
        # La agrego a la chain de INPUT
        comando = [self._ruta, "-A INPUT", "-j", tabla]
        subprocess.call(comando)

    @abc.abstractmethod
    def finalizar(self, tabla="zimbra-block"):
        comando = [self._ruta, "-F", tabla]
        exit_code = subprocess.call(comando)
        comando = [self._ruta, "-X", tabla]
        exit_code = subprocess.call(comando)


def _getTiempoFuturo(horas=6):
    """Devuelve la fecha actual+ x horas en el formato que le sirve a iptables"""
    return (datetime.now() + timedelta(hours=horas)).strftime("%Y:%m:%d:%H:%M")


def getFirewall():
    "Funcion de ayuda para obtener la clase de firewall"
    ruta = which("firewall-cmd")
    if ruta:
        return Firewall(FirewallD(ruta))

    ruta = which("iptables")
    if ruta:
        return Firewall(Iptables(ruta))

    raise OSError("No se encontro firewall-cmd ni iptables.")
