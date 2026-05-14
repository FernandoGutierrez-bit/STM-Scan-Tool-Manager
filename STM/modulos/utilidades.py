# Scan Tool Manager (STM)
# Integrantes: Gabriel Aguiñaga Ruiz, Fernando De Jesús Gutiérrez,
#              López Eliseo Ojeda Hernández, Eduardo Velazquez Zepeda,
#              Pablo Javier Mora Delgadillo

import os
import hashlib
import logging
import json
import base64
from datetime import datetime
from pathlib import Path

BASE_DIR       = Path(__file__).parent.parent
LOGS_DIR       = BASE_DIR / "logs"
RESULTADOS_DIR = BASE_DIR / "resultados"

LOGS_DIR.mkdir(exist_ok=True)
RESULTADOS_DIR.mkdir(exist_ok=True)


# Configurar logger
def configurar_logger(nombre: str) -> logging.Logger:
    logger = logging.getLogger(nombre)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    log_file = LOGS_DIR / f"{nombre}_{datetime.now().strftime('%Y%m%d')}.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# Hash de archivo
def calcular_hash_archivo(ruta: str, algoritmo: str = "sha256") -> str:
    try:
        h = hashlib.new(algoritmo)
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(8192), b""):
                h.update(bloque)
        return h.hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"Archivo no encontrado: {ruta}")
    except ValueError:
        raise ValueError(f"Algoritmo no soportado: {algoritmo}")


# Hash de texto
def calcular_hash_texto(texto: str, algoritmo: str = "sha256") -> str:
    h = hashlib.new(algoritmo)
    h.update(texto.encode("utf-8"))
    return h.hexdigest()


# Codificacion Base64
def codificar_base64(texto: str) -> str:
    return base64.b64encode(texto.encode("utf-8")).decode("utf-8")


def decodificar_base64(texto_b64: str) -> str:
    return base64.b64decode(texto_b64.encode("utf-8")).decode("utf-8")


# Guardar JSON
def guardar_json(datos: dict, nombre_archivo: str) -> str:
    ruta = RESULTADOS_DIR / nombre_archivo
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    return str(ruta)


# Cargar JSON
def cargar_json(ruta: str) -> dict:
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)


# Timestamp legible
def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Timestamp para nombres de archivo
def timestamp_archivo() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")
