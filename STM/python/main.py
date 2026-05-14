# Scan Tool Manager (STM)
# Integrantes: Gabriel Aguiñaga Ruiz, Fernando De Jesús Gutiérrez,
#              López Eliseo Ojeda Hernández, Eduardo Velazquez Zepeda,
#              Pablo Javier Mora Delgadillo

import os
import sys
import json
import subprocess
import platform
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

from modulos.utilidades import configurar_logger, guardar_json, timestamp
from modulos.analizador import (
    analizar_puertos_abiertos,
    analizar_procesos,
    correlacionar_hallazgos,
    calcular_score_riesgo,
)
from modulos.graficas import grafica_alertas, generar_grafica_matplotlib
from python.generador_reportes import generar_reporte_html, generar_reporte_json

logger = configurar_logger("main")

RESULTADOS_DIR = BASE_DIR / "resultados"
RESULTADOS_DIR.mkdir(exist_ok=True)

ES_WINDOWS = platform.system() == "Windows"


# Ejecutar Bash
def ejecutar_bash(script: str, args: list = None) -> bool:
    args = args or []
    ruta = BASE_DIR / "bash" / script
    cmd = ["bash", str(ruta)] + args
    logger.info(f"Ejecutando script Bash: {script} {' '.join(args)}")
    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if resultado.returncode != 0:
            logger.error(f"Error en {script}: {resultado.stderr}")
            return False
        logger.info(f"{script} completado exitosamente")
        return True
    except FileNotFoundError:
        logger.error("bash no encontrado. En Windows instala Git Bash.")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout ejecutando {script}")
        return False
    except Exception as e:
        logger.error(f"Excepcion ejecutando {script}: {e}")
        return False


# Ejecutar PowerShell
def ejecutar_powershell(script: str, args: list = None) -> bool:
    args = args or []
    ruta = BASE_DIR / "powershell" / script
    cmd = [
        "powershell",
        "-WindowStyle", "Hidden",
        "-ExecutionPolicy", "Bypass",
        "-NonInteractive",
        "-File", str(ruta),
    ] + args
    logger.info(f"Ejecutando script PowerShell: {script} {' '.join(args)}")
    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if resultado.returncode != 0:
            logger.error(f"Error en {script}: {resultado.stderr}")
            return False
        logger.info(f"{script} completado exitosamente")
        return True
    except FileNotFoundError:
        logger.error("powershell no encontrado.")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout ejecutando {script}")
        return False
    except Exception as e:
        logger.error(f"Excepcion ejecutando {script}: {e}")
        return False


# Cargar JSON
def cargar_resultado(nombre_archivo: str) -> dict:
    ruta = RESULTADOS_DIR / nombre_archivo
    if not ruta.exists():
        logger.error(f"Archivo no encontrado: {ruta}")
        return {}
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error al leer {nombre_archivo}: {e}")
        return {}


# Pipeline principal
def ejecutar_pipeline(objetivo: str, api_key_abuse: str = "") -> dict:
    logger.info("=" * 60)
    logger.info(f"  Scan Tool Manager (STM) — Analizando: {objetivo}")
    logger.info("=" * 60)

    # Reconocimiento de red
    logger.info("[ 1/6 ] Reconocimiento de red...")
    ejecutar_bash("reconocimiento.sh", [
        objetivo,
        str(RESULTADOS_DIR / "reconocimiento.json")
    ])

    # Inteligencia web
    logger.info("[ 2/6 ] Consulta de inteligencia web...")
    bash_args = [objetivo, str(RESULTADOS_DIR / "informacion_web.json")]
    if api_key_abuse:
        bash_args.append(api_key_abuse)
    ejecutar_bash("informacion_web.sh", bash_args)

    # Windows Scan
    if ES_WINDOWS:
        logger.info("[ 3/6 ] Auditoria del sistema (PowerShell)...")
        ejecutar_powershell("auditoria_sistema.ps1", [
            "-OutputPath", str(RESULTADOS_DIR / "auditoria_sistema.json")
        ])
        logger.info("[ 4/6 ] Informacion de red (PowerShell)...")
        ejecutar_powershell("informacion_red.ps1", [
            "-OutputPath", str(RESULTADOS_DIR / "informacion_red.json")
        ])
    else:
        logger.info("[ 3-4/6 ] Sistema no Windows, omitiendo scripts PowerShell")

    # Analisis y correlacion
    logger.info("[ 5/6 ] Analizando hallazgos...")
    recon            = cargar_resultado("reconocimiento.json")
    web              = cargar_resultado("informacion_web.json")
    auditoria        = cargar_resultado("auditoria_sistema.json")
    puertos_raw      = [{"puerto": p, "servicio": str(p)} for p in recon.get("puertos_abiertos", [])]
    analisis_red     = analizar_puertos_abiertos(puertos_raw)
    procesos_raw     = auditoria.get("procesos", [])
    analisis_sistema = analizar_procesos(procesos_raw)
    abuse_data       = web.get("abuseipdb", {}).get("data", {})
    datos_web = {
        "alertas": [],
        "ips_analizadas": [abuse_data] if abuse_data.get("abuseConfidenceScore", 0) > 0 else [],
        "pais": web.get("ipinfo", {}).get("country", ""),
    }
    correlacion = correlacionar_hallazgos(analisis_sistema, analisis_red, datos_web)
    score       = calcular_score_riesgo(correlacion)
    logger.info(f"Alertas: {correlacion['total_alertas']} | Score: {score}/100")

    # Gen-Logs y Reportes
    logger.info("[ 6/6 ] Generando reportes...")
    resultado_final = {
        "timestamp":      timestamp(),
        "objetivo":       objetivo,
        "score_riesgo":   score,
        "correlacion":    correlacion,
        "reconocimiento": recon,
        "web":            web,
        "auditoria":      auditoria,
    }
    print(grafica_alertas(correlacion))
    datos_grafica = {
        "CRITICO": correlacion.get("criticas", 0),
        "ALTO":    correlacion.get("altas",    0),
        "MEDIO":   correlacion.get("medias",   0),
        "BAJO":    correlacion.get("bajas",    0),
    }
    ruta_png  = generar_grafica_matplotlib(datos_grafica, f"STM — Score de Riesgo: {score}/100", "grafica_alertas.png")
    ruta_json = generar_reporte_json(resultado_final)
    ruta_html = generar_reporte_html(resultado_final)
    guardar_json(resultado_final, "resultado_completo.json")
    logger.info(f"Grafica: {ruta_png} | JSON: {ruta_json} | HTML: {ruta_html}")
    logger.info("=" * 60)
    logger.info(f"  Analisis finalizado. Score global: {score}/100")
    logger.info("=" * 60)
    return resultado_final


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan Tool Manager (STM) — Herramienta de automatizacion para ciberseguridad"
    )
    parser.add_argument("objetivo", nargs="?", default="localhost", help="IP o dominio a analizar")
    parser.add_argument("--abuse-key", default="", help="API key de AbuseIPDB")
    args = parser.parse_args()
    ejecutar_pipeline(args.objetivo, args.abuse_key)
