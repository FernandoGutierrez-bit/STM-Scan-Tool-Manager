# Scan Tool Manager (STM)
# Integrantes: Gabriel Aguiñaga Ruiz, Fernando De Jesús Gutiérrez,
#              López Eliseo Ojeda Hernández, Eduardo Velazquez Zepeda,
#              Pablo Javier Mora Delgadillo

from typing import List, Dict

PUERTOS_PELIGROSOS: Dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    445:  "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}


# Filtrar puertos peligrosos
def filtrar_puertos_peligrosos(puertos: list) -> list:
    resultado = []
    for p in puertos:
        numero = int(p.get("puerto", 0)) if isinstance(p, dict) else int(p)
        if numero in PUERTOS_PELIGROSOS:
            resultado.append({
                "puerto":   numero,
                "servicio": PUERTOS_PELIGROSOS[numero],
            })
    return resultado


# Normalizar proceso
def normalizar_proceso(proceso: dict) -> dict:
    return {
        "nombre":     str(proceso.get("nombre", "desconocido")).lower().strip(),
        "pid":        int(proceso.get("pid", 0)),
        "memoria_mb": float(proceso.get("memoria_mb", 0)),
        "cpu":        float(proceso.get("cpu", 0)),
        "ruta":       str(proceso.get("ruta", "N/A")),
    }


# Limpiar lista de procesos
def limpiar_lista_procesos(procesos: list) -> list:
    return [normalizar_proceso(p) for p in procesos if isinstance(p, dict)]


# Limpiar IP
def limpiar_ip(ip: str) -> str:
    return ip.strip().replace(" ", "")


# Verificar IP privada
def es_ip_privada(ip: str) -> bool:
    ip = limpiar_ip(ip)
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.31.")
        or ip == "127.0.0.1"
    )
