<#
.SYNOPSIS
    Auditoría de seguridad del sistema Windows para Scan Tool Manager (STM).
.DESCRIPTION
    Recolecta: info del SO, usuarios, procesos, servicios, puertos en escucha
    y conexiones de red activas. Guarda el resultado en JSON para que Python
    lo analice en la siguiente etapa del pipeline.
.PARAMETER OutputPath
    Ruta del archivo JSON de salida.
    Default: ..\resultados\auditoria_sistema.json
.PARAMETER FullScan
    Si se especifica, incluye eventos de seguridad del visor de eventos
    (requiere permisos de administrador).
.EXAMPLE
    .\auditoria_sistema.ps1
    .\auditoria_sistema.ps1 -OutputPath "..\resultados\auditoria.json" -FullScan
#>

param(
    [string]$OutputPath = "..\resultados\auditoria_sistema.json",
    [switch]$FullScan
)

# ──────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Mensaje, [string]$Nivel = "INFO")
    $ts      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linea   = "[$ts] [$Nivel] $Mensaje"
    Write-Host $linea
    $logDir  = "..\logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    Add-Content -Path "$logDir\auditoria_$(Get-Date -Format 'yyyyMMdd').log" -Value $linea -Encoding UTF8
}

Write-Log "========================================================"
Write-Log "  Scan Tool Manager (STM) - Auditoría del Sistema"
Write-Log "========================================================"

# ──────────────────────────────────────────────────────────────
# ESTRUCTURA BASE
# ──────────────────────────────────────────────────────────────
$resultado = @{
    timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    hostname        = $env:COMPUTERNAME
    usuario_actual  = $env:USERNAME
    sistema         = @{}
    usuarios        = @()
    procesos        = @()
    servicios       = @()
    conexiones      = @()
    puertos         = @()
    eventos         = @()
    hash_auditoria  = ""
}

# ──────────────────────────────────────────────────────────────
# 1. INFORMACIÓN DEL SISTEMA OPERATIVO
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Recolectando información del sistema operativo..."
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    $resultado.sistema = @{
        nombre_os       = $os.Caption
        version         = $os.Version
        arquitectura    = $os.OSArchitecture
        ultimo_reinicio = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        ram_total_gb    = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        ram_libre_gb    = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        dominio         = $cs.Domain
    }
    Write-Log "Sistema OS: $($os.Caption) — RAM libre: $($resultado.sistema.ram_libre_gb) GB"
} catch {
    Write-Log "Error al obtener información del SO: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 2. USUARIOS LOCALES
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Recolectando usuarios del sistema..."
    $resultado.usuarios = Get-LocalUser | ForEach-Object {
        @{
            nombre              = $_.Name
            habilitado          = $_.Enabled
            ultimo_acceso       = if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { "Nunca" }
            contrasena_expira   = if ($_.PasswordExpires) { $_.PasswordExpires.ToString("yyyy-MM-dd") } else { "Nunca" }
            descripcion         = if ($_.Description) { $_.Description } else { "" }
        }
    }
    Write-Log "Usuarios encontrados: $($resultado.usuarios.Count)"
} catch {
    Write-Log "Error al obtener usuarios: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 3. PROCESOS ACTIVOS
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Recolectando procesos activos..."
    $resultado.procesos = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            nombre      = $_.Name
            pid         = $_.Id
            memoria_mb  = [math]::Round($_.WorkingSet / 1MB, 2)
            cpu         = if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 }
            ruta        = if ($_.Path) { $_.Path } else { "N/A" }
        }
    }
    Write-Log "Procesos recolectados: $($resultado.procesos.Count)"
} catch {
    Write-Log "Error al obtener procesos: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 4. SERVICIOS DEL SISTEMA
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Recolectando servicios..."
    $resultado.servicios = Get-Service | ForEach-Object {
        @{
            nombre       = $_.Name
            nombre_largo = $_.DisplayName
            estado       = $_.Status.ToString()
            tipo_inicio  = $_.StartType.ToString()
        }
    }
    $activos = ($resultado.servicios | Where-Object { $_.estado -eq "Running" }).Count
    Write-Log "Servicios: $($resultado.servicios.Count) total, $activos en ejecución"
} catch {
    Write-Log "Error al obtener servicios: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 5. CONEXIONES DE RED Y PUERTOS
# ──────────────────────────────────────────────────────────────
try {
    Write-Log "Recolectando conexiones de red..."
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue

    $resultado.conexiones = $conns | ForEach-Object {
        @{
            ip_local      = $_.LocalAddress
            puerto_local  = $_.LocalPort
            ip_remota     = $_.RemoteAddress
            puerto_remoto = $_.RemotePort
            estado        = $_.State.ToString()
            pid           = $_.OwningProcess
        }
    }

    # Puertos únicos en escucha (LISTEN)
    $resultado.puertos = ($conns | Where-Object { $_.State -eq "Listen" } |
        Select-Object -ExpandProperty LocalPort | Sort-Object -Unique)

    Write-Log "Conexiones activas: $($resultado.conexiones.Count)"
    Write-Log "Puertos en escucha: $($resultado.puertos.Count)"
} catch {
    Write-Log "Error al obtener conexiones de red: $_" "ERROR"
}

# ──────────────────────────────────────────────────────────────
# 6. EVENTOS DE SEGURIDAD  (solo con -FullScan)
# ──────────────────────────────────────────────────────────────
if ($FullScan) {
    try {
        Write-Log "Recolectando eventos de seguridad (FullScan activado)..."
        # IDs relevantes: logon exitoso (4624), fallo (4625), cuenta creada (4720), eliminada (4726)
        $resultado.eventos = Get-EventLog -LogName Security -Newest 100 -ErrorAction SilentlyContinue |
            Where-Object { $_.EventID -in @(4624, 4625, 4648, 4720, 4726) } |
            ForEach-Object {
                @{
                    id        = $_.EventID
                    tipo      = $_.EntryType.ToString()
                    timestamp = $_.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
                    mensaje   = $_.Message.Substring(0, [math]::Min(300, $_.Message.Length))
                }
            }
        Write-Log "Eventos de seguridad recolectados: $($resultado.eventos.Count)"
    } catch {
        Write-Log "No se pudieron obtener eventos (se requieren permisos de Administrador): $_" "WARN"
    }
}

# ──────────────────────────────────────────────────────────────
# 7. GUARDAR JSON + HASH DE INTEGRIDAD
# ──────────────────────────────────────────────────────────────
try {
    $outDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    # Primera escritura
    $json = $resultado | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputPath -Encoding utf8 -Force

    # Calcular hash SHA-256 del archivo generado
    $hash = Get-FileHash -Path $OutputPath -Algorithm SHA256
    $resultado.hash_auditoria = $hash.Hash

    # Reescribir con hash incluido
    ($resultado | ConvertTo-Json -Depth 10) | Out-File -FilePath $OutputPath -Encoding utf8 -Force

    Write-Log "Resultado guardado en: $OutputPath"
    Write-Log "SHA-256 del archivo: $($hash.Hash)"
} catch {
    Write-Log "Error crítico al guardar resultado: $_" "ERROR"
    exit 1
}

Write-Log "Auditoría del sistema completada exitosamente"
Write-Log "========================================================"