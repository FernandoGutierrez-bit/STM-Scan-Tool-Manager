<#
.SYNOPSIS
    Recolección de información de red del sistema Windows para Scan Tool Manager (STM).
.DESCRIPTION
    Obtiene interfaces, tabla ARP, rutas, configuración DNS e IP pública.
    Se ejecuta en modo silencioso (sin ventana visible) cuando se invoca desde main.py.
.PARAMETER OutputPath
    Ruta del archivo JSON de salida.
.EXAMPLE
    .\informacion_red.ps1
    .\informacion_red.ps1 -OutputPath "..\resultados\red.json"
#>

param(
    [string]$OutputPath = "..\resultados\informacion_red.json"
)

function Write-Log {
    param([string]$Mensaje, [string]$Nivel = "INFO")
    $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linea = "[$ts] [$Nivel] $Mensaje"
    Write-Host $linea
    $logDir = "..\logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    Add-Content -Path "$logDir\red_$(Get-Date -Format 'yyyyMMdd').log" -Value $linea -Encoding UTF8
}

Write-Log "Iniciando recolección de información de red..."

$resultado = @{
    timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    hostname    = $env:COMPUTERNAME
    interfaces  = @()
    tabla_arp   = @()
    rutas       = @()
    dns_config  = @()
    ip_publica  = ""
    adaptadores = @()
}

# ──────────────────────────────────────────────────────────────
# 1. INTERFACES DE RED
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Obteniendo interfaces de red..."
    $resultado.interfaces = Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            interfaz  = $_.InterfaceAlias
            familia   = $_.AddressFamily.ToString()
            ip        = $_.IPAddress
            prefijo   = $_.PrefixLength
        }
    }
    Write-Log "Interfaces encontradas: $($resultado.interfaces.Count)"
} catch {
    Write-Log "Error al obtener interfaces: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 2. TABLA ARP
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Obteniendo tabla ARP..."
    $resultado.tabla_arp = Get-NetNeighbor -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            interfaz = $_.InterfaceAlias
            ip       = $_.IPAddress
            mac      = $_.LinkLayerAddress
            estado   = $_.State.ToString()
        }
    }
    Write-Log "Entradas ARP: $($resultado.tabla_arp.Count)"
} catch {
    Write-Log "Error al obtener tabla ARP: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 3. TABLA DE RUTAS
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Obteniendo tabla de rutas..."
    $resultado.rutas = Get-NetRoute -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            interfaz = $_.InterfaceAlias
            destino  = $_.DestinationPrefix
            gateway  = $_.NextHop
            metrica  = $_.RouteMetric
        }
    }
    Write-Log "Rutas encontradas: $($resultado.rutas.Count)"
} catch {
    Write-Log "Error al obtener rutas: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 4. CONFIGURACIÓN DNS
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Obteniendo configuración DNS..."
    $resultado.dns_config = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            interfaz   = $_.InterfaceAlias
            servidores = $_.ServerAddresses
        }
    }
} catch {
    Write-Log "Error al obtener DNS: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 5. IP PÚBLICA  (via API pública — sin autenticación)
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Obteniendo IP pública via api.ipify.org..."
    $resp = Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 10 -ErrorAction Stop
    $resultado.ip_publica = $resp.ip
    Write-Log "IP pública detectada: $($resultado.ip_publica)"
} catch {
    Write-Log "No se pudo obtener la IP pública: $_" "WARN"
    $resultado.ip_publica = "No disponible"
}

# ──────────────────────────────────────────────────────────────
# 6. ADAPTADORES
# ──────────────────────────────────────────────────────────────
try {
    $resultado.adaptadores = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            nombre      = $_.Name
            descripcion = $_.InterfaceDescription
            mac         = $_.MacAddress
            estado      = $_.Status.ToString()
            velocidad   = "$([math]::Round($_.LinkSpeed / 1MB, 0)) Mbps"
        }
    }
} catch {
    Write-Log "Error al obtener adaptadores: $_" "WARN"
}

# ──────────────────────────────────────────────────────────────
# 7. GUARDAR RESULTADO
# ──────────────────────────────────────────────────────────────
try {
    $outDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    ($resultado | ConvertTo-Json -Depth 10) | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Log "Información de red guardada en: $OutputPath"
} catch {
    Write-Log "Error al guardar resultado: $_" "ERROR"
    exit 1
}

Write-Log "Recolección de información de red completada"