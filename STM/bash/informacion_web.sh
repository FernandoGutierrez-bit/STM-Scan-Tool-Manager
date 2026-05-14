#!/bin/bash
# ==============================================================================
#  informacion_web.sh — Inteligencia de amenazas y reputación de IP/dominio
#  Compatible con Git Bash (Windows) y Linux/macOS
#
#  Uso:  ./informacion_web.sh [ip_o_dominio] [salida] [api_key_abuseipdb]
#  Ej:   ./informacion_web.sh 8.8.8.8 ../resultados/web.json
#        ./informacion_web.sh 8.8.8.8 ../resultados/web.json MI_API_KEY
#
#  API gratuita de AbuseIPDB: https://www.abuseipdb.com/register
# ==============================================================================

OBJETIVO="${1:-8.8.8.8}"
OUTPUT="${2:-../resultados/informacion_web.json}"
ABUSEIPDB_KEY="${3:-}"          # Opcional
LOG_DIR="../logs"
LOG_FILE="$LOG_DIR/web_$(date +%Y%m%d).log"
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
# VERIFICAR DEPENDENCIAS
# ──────────────────────────────────────────────────────────────
if ! command -v curl &>/dev/null; then
    log "ERROR" "curl no está instalado. En Git Bash ya viene incluido."
    exit 1
fi

log "INFO" "================================================================"
log "INFO" "  Scan Tool Manager (STM) - Inteligencia Web"
log "INFO" "  Objetivo: $OBJETIVO"
log "INFO" "================================================================"

# ──────────────────────────────────────────────────────────────
# 1. INFORMACIÓN GEOGRÁFICA Y DE ORG  (ipinfo.io — sin API key)
# ──────────────────────────────────────────────────────────────
log "INFO" "Consultando ipinfo.io..."
IPINFO=$(curl -s --max-time 10 "https://ipinfo.io/${OBJETIVO}/json" 2>/dev/null)

if [ -z "$IPINFO" ]; then
    log "WARN" "Sin respuesta de ipinfo.io"
    IPINFO='{"error": "Sin respuesta"}'
else
    log "INFO" "ipinfo.io respondió correctamente"
fi

# ──────────────────────────────────────────────────────────────
# 2. REPUTACIÓN EN ABUSEIPDB  (requiere API key gratuita)
# ──────────────────────────────────────────────────────────────
if [ -n "$ABUSEIPDB_KEY" ]; then
    log "INFO" "Consultando AbuseIPDB..."
    ABUSE=$(curl -s --max-time 10 \
        -G "https://api.abuseipdb.com/api/v2/check" \
        --data-urlencode "ipAddress=$OBJETIVO" \
        -d "maxAgeInDays=90" \
        -H "Key: $ABUSEIPDB_KEY" \
        -H "Accept: application/json" 2>/dev/null)

    if [ -z "$ABUSE" ]; then
        log "WARN" "Sin respuesta de AbuseIPDB"
        ABUSE='{"data":{"abuseConfidenceScore":0,"nota":"Sin respuesta"}}'
    else
        SCORE=$(echo "$ABUSE" | grep -o '"abuseConfidenceScore":[0-9]*' | grep -o '[0-9]*')
        log "INFO" "AbuseIPDB — Score de abuso: ${SCORE:-0}%"
    fi
else
    log "WARN" "API key de AbuseIPDB no proporcionada — omitiendo verificación de reputación"
    ABUSE='{"data":{"abuseConfidenceScore":0,"nota":"API key no configurada — registrate gratis en abuseipdb.com"}}'
fi

# ──────────────────────────────────────────────────────────────
# 3. DNS INVERSO  (Google DNS API — sin API key)
# ──────────────────────────────────────────────────────────────
log "INFO" "Consultando DNS inverso via dns.google..."
DNS_INV=$(curl -s --max-time 10 \
    "https://dns.google/resolve?name=${OBJETIVO}&type=PTR" 2>/dev/null)

if [ -z "$DNS_INV" ]; then
    log "WARN" "Sin respuesta de dns.google"
    DNS_INV='{"Status":-1,"error":"Sin respuesta"}'
fi

# ──────────────────────────────────────────────────────────────
# 4. HASH SHA-256 DEL OBJETIVO  (codificación para auditoría)
# ──────────────────────────────────────────────────────────────
if command -v sha256sum &>/dev/null; then
    HASH=$(echo -n "$OBJETIVO" | sha256sum | awk '{print $1}')
elif command -v shasum &>/dev/null; then
    HASH=$(echo -n "$OBJETIVO" | shasum -a 256 | awk '{print $1}')
else
    HASH="no_disponible"
fi
log "INFO" "Hash SHA-256 del objetivo: $HASH"

# ──────────────────────────────────────────────────────────────
# 5. CODIFICACIÓN BASE64  (técnica de codificación requerida)
# ──────────────────────────────────────────────────────────────
if command -v base64 &>/dev/null; then
    B64=$(echo -n "$OBJETIVO" | base64)
else
    B64="no_disponible"
fi
log "INFO" "Objetivo en Base64: $B64"

# ──────────────────────────────────────────────────────────────
# 6. GENERAR JSON DE SALIDA
# ──────────────────────────────────────────────────────────────
cat > "$OUTPUT" << ENDJSON
{
  "timestamp": "$TIMESTAMP",
  "objetivo": "$OBJETIVO",
  "objetivo_base64": "$B64",
  "hash_sha256": "$HASH",
  "ipinfo": $IPINFO,
  "abuseipdb": $ABUSE,
  "dns_inverso": $DNS_INV,
  "herramienta": "informacion_web.sh"
}
ENDJSON

log "INFO" "Información web guardada en: $OUTPUT"
log "INFO" "Consulta de inteligencia web completada"