# Scan Tool Manager (STM)
# Integrantes: Gabriel Aguiñaga Ruiz, Fernando De Jesús Gutiérrez,
#              López Eliseo Ojeda Hernández, Eduardo Velazquez Zepeda,
#              Pablo Javier Mora Delgadillo

from typing import List, Dict

NIVEL_RIESGO: Dict[str, int] = {
    "CRITICO": 4,
    "ALTO":    3,
    "MEDIO":   2,
    "BAJO":    1,
    "INFO":    0,
}

PROCESOS_MALICIOSOS = [
    "mimikatz", "nc", "netcat", "nmap", "wireshark", "metasploit",
    "msfconsole", "powersploit", "psexec", "wce", "pwdump", "fgdump",
    "wmiexec", "crackmapexec", "cobaltstrike", "empire", "bloodhound",
]

PAISES_ALTO_RIESGO = {"RU", "CN", "KP", "IR", "BY", "SY"}


# Evaluar riesgo de IP
def evaluar_nivel_riesgo_ip(datos_ip: dict) -> str:
    puntuacion = datos_ip.get("abuseConfidenceScore", 0)
    if puntuacion >= 80:
        return "CRITICO"
    if puntuacion >= 50:
        return "ALTO"
    if puntuacion >= 20:
        return "MEDIO"
    if puntuacion > 0:
        return "BAJO"
    return "INFO"


# Analizar puertos abiertos
def analizar_puertos_abiertos(puertos: list) -> dict:
    from modulos.limpiador_datos import filtrar_puertos_peligrosos
    peligrosos = filtrar_puertos_peligrosos(puertos)
    alertas = []

    for p in peligrosos:
        alertas.append({
            "tipo":          "PUERTO_RIESGO",
            "nivel":         "ALTO",
            "descripcion":   f"Puerto {p['puerto']} ({p['servicio']}) abierto, servicio sensible expuesto",
            "recomendacion": f"Verificar si {p['servicio']} es necesario y esta protegido con autenticacion fuerte",
        })

    puertos_criticos = {3389: "RDP", 23: "Telnet"}
    for p in peligrosos:
        if p["puerto"] in puertos_criticos:
            alertas.append({
                "tipo":          "SERVICIO_CRITICO_EXPUESTO",
                "nivel":         "CRITICO",
                "descripcion":   f"Servicio {puertos_criticos[p['puerto']]} (puerto {p['puerto']}) detectado, acceso remoto expuesto",
                "recomendacion": "Restringir acceso mediante firewall o VPN de inmediato",
            })

    return {
        "total_puertos":      len(puertos),
        "puertos_peligrosos": len(peligrosos),
        "alertas":            alertas,
        "detalle":            peligrosos,
    }


# Analizar procesos activos
def analizar_procesos(procesos: list) -> dict:
    alertas = []

    for p in procesos:
        nombre  = str(p.get("nombre", "")).lower()
        memoria = float(p.get("memoria_mb", 0))
        pid     = p.get("pid", "?")

        if any(mal in nombre for mal in PROCESOS_MALICIOSOS):
            alertas.append({
                "tipo":          "PROCESO_SOSPECHOSO",
                "nivel":         "CRITICO",
                "descripcion":   f"Proceso sospechoso detectado: '{nombre}' (PID: {pid})",
                "recomendacion": "Terminar el proceso inmediatamente e investigar su origen",
            })

        if memoria > 500:
            alertas.append({
                "tipo":          "ALTO_CONSUMO_RAM",
                "nivel":         "MEDIO",
                "descripcion":   f"Proceso '{nombre}' (PID: {pid}) consume {memoria} MB de RAM",
                "recomendacion": "Verificar si este consumo es normal para la aplicacion",
            })

    altos_recursos = [p for p in procesos if float(p.get("memoria_mb", 0)) > 200]

    return {
        "total_procesos":        len(procesos),
        "alertas":               alertas,
        "procesos_alto_consumo": altos_recursos,
    }


# Correlacionar hallazgos
def correlacionar_hallazgos(datos_sistema: dict, datos_red: dict, datos_web: dict) -> dict:
    todas_alertas: List[dict] = []

    todas_alertas += datos_sistema.get("alertas", [])
    todas_alertas += datos_red.get("alertas", [])
    todas_alertas += datos_web.get("alertas", [])

    for ip_data in datos_web.get("ips_analizadas", []):
        nivel = evaluar_nivel_riesgo_ip(ip_data)
        if nivel in ("CRITICO", "ALTO"):
            todas_alertas.append({
                "tipo":          "IP_MALICIOSA",
                "nivel":         nivel,
                "descripcion":   f"IP {ip_data.get('ipAddress', '?')} con {ip_data.get('abuseConfidenceScore', 0)}% de confianza de abuso",
                "recomendacion": "Bloquear esta IP en el firewall de inmediato",
            })

    pais = datos_web.get("pais", "")
    if pais in PAISES_ALTO_RIESGO:
        todas_alertas.append({
            "tipo":          "PAIS_ALTO_RIESGO",
            "nivel":         "MEDIO",
            "descripcion":   f"Trafico detectado hacia/desde pais de alto riesgo: {pais}",
            "recomendacion": "Monitorear y considerar bloquear trafico a este destino geografico",
        })

    todas_alertas.sort(
        key=lambda x: NIVEL_RIESGO.get(x.get("nivel", "INFO"), 0),
        reverse=True
    )

    return {
        "total_alertas": len(todas_alertas),
        "criticas":      sum(1 for a in todas_alertas if a["nivel"] == "CRITICO"),
        "altas":         sum(1 for a in todas_alertas if a["nivel"] == "ALTO"),
        "medias":        sum(1 for a in todas_alertas if a["nivel"] == "MEDIO"),
        "bajas":         sum(1 for a in todas_alertas if a["nivel"] == "BAJO"),
        "alertas":       todas_alertas,
    }


# Calcular score de riesgo
def calcular_score_riesgo(correlacion: dict) -> int:
    score = (
        correlacion.get("criticas", 0) * 30 +
        correlacion.get("altas",    0) * 15 +
        correlacion.get("medias",   0) *  5 +
        correlacion.get("bajas",    0) *  1
    )
    return min(score, 100)
