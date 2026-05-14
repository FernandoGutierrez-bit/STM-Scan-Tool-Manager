#!/bin/bash
# ==============================================================================
#  reconocimiento.sh — Reconocimiento básico de red para Scan Tool Manager (STM)
#  Compatible con Git Bash (Windows) y Linux/macOS
#
#  Uso: ./reconocimiento.sh [objetivo] [archivo_salida]
#  Ej:  ./reconocimiento.sh example.com ../resultados/recon.json
#       ./reconocimiento.sh 192.168.1.1
# ==============================================================================

# ──────────────────────────────────────────────────────────────
# ARGUMENTOS Y CONFIGURACIÓN
# ──────────────────────────────────────────────────────────────
OBJETIVO="${1:-localhost}"
OUTPUT="${2:-../resultados/reconocimiento.json}"
LOG_DIR="../logs"
LOG_FILE="$LOG_DIR/recon_$(date +%Y%m%d).log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$OUTPUT")"

# ──────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────
log() {
    local nivel="$1"
    local mensaje="$2"
    local linea="[$TIMESTAMP] [$nivel] $mensaje"
    echo "$linea"
    echo "$linea" >> "$LOG_FILE"
}

# ──────────────────────────────────────────────────────────────
# VALIDACIÓN DE ARGUMENTOS
# ──────────────────────────────────────────────────────────────
if [ -z "$OBJETIVO" ]; then
    log "ERROR" "Debe especificar un objetivo (dominio o IP)"
    echo "Uso: $0 [dominio_o_ip] [archivo_salida]"
    exit 1
fi

log "INFO" "================================================================"
log "INFO" "  Scan Tool Manager (STM) - Reconocimiento de Red"
log "INFO" "  Objetivo: $OBJETIVO"
log "INFO" "================================================================"

# ──────────────────────────────────────────────────────────────
# FUNCIÓN: RESOLUCIÓN DNS
# ──────────────────────────────────────────────────────────────
obtener_ips_dns() {
    local target="$1"
    local resultado=""
    log "INFO" "Resolviendo DNS de $target..."

    if command -v nslookup &>/dev/null; then
        resultado=$(nslookup "$target" 2>/dev/null \
            | grep -E "^Address:" | tail -n +2 \
            | awk '{print $2}' \
            | tr '\n' ',' | sed 's/,$//')
    elif command -v host &>/dev/null; then
        resultado=$(host "$target" 2>/dev/null \
            | grep "has address" \
            | awk '{print $4}' \
            | tr '\n' ',' | sed 's/,$//')
    else
        resultado="N/A"
    fi

    [ -z "$resultado" ] && resultado="No resuelto"
    echo "$resultado"
}

# ──────────────────────────────────────────────────────────────
# FUNCIÓN: PING
# ──────────────────────────────────────────────────────────────
hacer_ping() {
    local target="$1"
    log "INFO" "Enviando ping a $target..."

    # Windows (ping -n) vs Linux (ping -c)
    if ping -n 3 "$target" &>/dev/null 2>&1; then
        echo "true"
    elif ping -c 3 "$target" &>/dev/null 2>&1; then
        echo "true"
    else
        echo "false"
    fi
}

# ──────────────────────────────────────────────────────────────
# FUNCIÓN: TRACEROUTE
# ──────────────────────────────────────────────────────────────
hacer_traceroute() {
    local target="$1"
    local resultado=""
    log "INFO" "Ejecutando traceroute hacia $target..."

    if command -v tracert &>/dev/null; then
        resultado=$(tracert -h 8 "$target" 2>/dev/null | tail -n +5 | head -8)
    elif command -v traceroute &>/dev/null; then
        resultado=$(traceroute -m 8 "$target" 2>/dev/null | tail -n +2 | head -8)
    else
        resultado="traceroute no disponible"
    fi

    # Limpiar caracteres problemáticos para JSON
    echo "$resultado" | tr -d '"\\' | tr '\n' ' '
}

# ──────────────────────────────────────────────────────────────
# FUNCIÓN: ESCANEO DE PUERTOS (sin nmap, usando /dev/tcp)
# ──────────────────────────────────────────────────────────────
escanear_puertos() {
    local target="$1"
    local abiertos=()
    local PUERTOS=(21 22 23 25 53 80 110 135 139 143 443 445 3306 3389 5900 8080)

    log "INFO" "Escaneando ${#PUERTOS[@]} puertos en $target (timeout 1s por puerto)..."

    for puerto in "${PUERTOS[@]}"; do
        if (echo >/dev/tcp/"$target"/"$puerto") 2>/dev/null; then
            abiertos+=("$puerto")
            log "INFO" "  Puerto ABIERTO: $puerto"
        fi
    done

    # Retornar como array JSON
    if [ ${#abiertos[@]} -gt 0 ]; then
        local json_array
        json_array=$(printf '%s\n' "${abiertos[@]}" | \
            awk 'BEGIN{printf "["} NR>1{printf ","} {printf "%s",$0} END{printf "]"}')
        echo "$json_array"
    else
        echo "[]"
    fi
}

# ──────────────────────────────────────────────────────────────
# EJECUCIÓN DE TODAS LAS FUNCIONES
# ──────────────────────────────────────────────────────────────
IPS_DNS=$(obtener_ips_dns "$OBJETIVO")
RESPONDE_PING=$(hacer_ping "$OBJETIVO")
TRACEROUTE=$(hacer_traceroute "$OBJETIVO")
PUERTOS_JSON=$(escanear_puertos "$OBJETIVO")

log "INFO" "IPs resueltas: $IPS_DNS"
log "INFO" "Responde ping: $RESPONDE_PING"
log "INFO" "Puertos abiertos: $PUERTOS_JSON"

# ──────────────────────────────────────────────────────────────
# HASH DEL OBJETIVO (auditoría)
# ──────────────────────────────────────────────────────────────
if command -v sha256sum &>/dev/null; then
    HASH_OBJETIVO=$(echo -n "$OBJETIVO" | sha256sum | awk '{print $1}')
elif command -v shasum &>/dev/null; then
    HASH_OBJETIVO=$(echo -n "$OBJETIVO" | shasum -a 256 | awk '{print $1}')
else
    HASH_OBJETIVO="no_disponible"
fi
log "INFO" "Hash SHA-256 del objetivo: $HASH_OBJETIVO"

# ──────────────────────────────────────────────────────────────
# GENERAR JSON DE SALIDA
# ──────────────────────────────────────────────────────────────
cat > "$OUTPUT" << ENDJSON
{
  "timestamp": "$TIMESTAMP",
  "objetivo": "$OBJETIVO",
  "hash_objetivo_sha256": "$HASH_OBJETIVO",
  "ips_resueltas": "$IPS_DNS",
  "responde_ping": $RESPONDE_PING,
  "puertos_abiertos": $PUERTOS_JSON,
  "traceroute": "$TRACEROUTE",
  "herramienta": "reconocimiento.sh"
}
ENDJSON

log "INFO" "Resultado guardado en: $OUTPUT"
log "INFO" "Reconocimiento completado"