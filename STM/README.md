# Scan Tool Manager (STM)

STM is a toolbox with simple automation scripts for managing network threats using PowerShell, Bash and Python.

## Integrantes del equipo

- Gabriel Aguiñaga Ruiz
- Fernando De Jesús Gutiérrez
- López Eliseo Ojeda Hernández
- Eduardo Velazquez Zepeda
- Pablo Javier Mora Delgadillo

## Estructura del Proyecto

```
STM/
├── powershell/
│   ├── auditoria_sistema.ps1    # Auditoría de usuarios, procesos y servicios
│   └── informacion_red.ps1      # Interfaces, ARP, rutas y DNS
├── bash/
│   ├── reconocimiento.sh        # DNS, ping, traceroute, escaneo de puertos
│   └── informacion_web.sh       # Reputación IP (ipinfo + AbuseIPDB)
├── python/
│   ├── main.py                  # Orquestador principal del pipeline
│   └── generador_reportes.py    # Generación de reportes HTML y JSON
├── modulos/
│   ├── utilidades.py            # Logging, hashing, base64, JSON
│   ├── analizador.py            # Detección de amenazas y correlación
│   ├── graficas.py              # Gráficas ASCII y matplotlib
│   └── limpiador_datos.py       # Normalización y filtrado de datos
├── logs/                        # Archivos de log por fecha
└── resultados/                  # JSONs, HTML y PNGs generados
```

## Requisitos

```bash
pip install requests matplotlib
```

## Uso

```bash
# Análisis básico
python python/main.py

# Análisis de un dominio o IP
python python/main.py example.com

# Con API key de AbuseIPDB (gratis en abuseipdb.com)
python python/main.py 8.8.8.8 --abuse-key TU_API_KEY
```

## Pipeline

1. **Bash** ejecuta reconocimiento de red (`reconocimiento.sh`)
2. **Bash** consulta inteligencia web (`informacion_web.sh`)
3. **PowerShell** audita el sistema Windows (`auditoria_sistema.ps1`)
4. **PowerShell** recolecta info de red (`informacion_red.ps1`)
5. **Python** analiza y correlaciona hallazgos
6. **Python** genera reportes HTML y JSON
