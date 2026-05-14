# Scan Tool Manager (STM)
# Integrantes: Gabriel Aguiñaga Ruiz, Fernando De Jesús Gutiérrez,
#              López Eliseo Ojeda Hernández, Eduardo Velazquez Zepeda,
#              Pablo Javier Mora Delgadillo

import json
from pathlib import Path
from datetime import datetime

BASE_DIR       = Path(__file__).parent.parent
RESULTADOS_DIR = BASE_DIR / "resultados"
RESULTADOS_DIR.mkdir(exist_ok=True)

NIVEL_COLORES = {
    "CRITICO": "#e74c3c",
    "ALTO":    "#e67e22",
    "MEDIO":   "#f1c40f",
    "BAJO":    "#2ecc71",
    "INFO":    "#3498db",
}


# Generar reporte JSON
def generar_reporte_json(datos: dict) -> str:
    ruta = RESULTADOS_DIR / f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    return str(ruta)


# Generar reporte HTML
def generar_reporte_html(datos: dict) -> str:
    objetivo    = datos.get("objetivo", "N/A")
    score       = datos.get("score_riesgo", 0)
    correlacion = datos.get("correlacion", {})
    ts          = datos.get("timestamp", "N/A")
    alertas     = correlacion.get("alertas", [])

    if score >= 70:
        color_score = "#e74c3c"
        nivel_score = "CRITICO"
    elif score >= 40:
        color_score = "#e67e22"
        nivel_score = "ALTO"
    elif score >= 20:
        color_score = "#f1c40f"
        nivel_score = "MEDIO"
    else:
        color_score = "#2ecc71"
        nivel_score = "BAJO"

    filas_alertas = ""
    for alerta in alertas:
        nivel = alerta.get("nivel", "INFO")
        color = NIVEL_COLORES.get(nivel, "#95a5a6")
        filas_alertas += f"""
        <tr>
            <td><span style="background:{color};color:#fff;padding:2px 8px;
                border-radius:4px;font-weight:bold;">{nivel}</span></td>
            <td>{alerta.get('tipo', '')}</td>
            <td>{alerta.get('descripcion', '')}</td>
            <td>{alerta.get('recomendacion', '')}</td>
        </tr>"""

    recon         = datos.get("reconocimiento", {})
    puertos_lista = recon.get("puertos_abiertos", [])
    puertos_str   = ", ".join(str(p) for p in puertos_lista) if puertos_lista else "Ninguno"
    web           = datos.get("web", {})
    ipinfo        = web.get("ipinfo", {})
    abuse         = web.get("abuseipdb", {}).get("data", {})
    score_ab      = abuse.get("abuseConfidenceScore", 0)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Scan Tool Manager (STM) — Reporte de Seguridad</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#0f0f1a; color:#e0e0e0; margin:0; padding:20px; }}
  .container {{ max-width:1100px; margin:auto; }}
  h1 {{ color:#4fc3f7; border-bottom:2px solid #333; padding-bottom:10px; }}
  h2 {{ color:#81d4fa; margin-top:30px; }}
  .score-box {{ display:inline-block; background:{color_score}; color:#fff;
               padding:15px 30px; border-radius:10px; font-size:2em; font-weight:bold; margin:10px 0; }}
  .nivel-badge {{ background:{color_score}; color:#fff; padding:5px 15px;
                 border-radius:20px; font-weight:bold; display:inline-block; margin-left:10px; vertical-align:middle; }}
  .stats {{ display:flex; gap:15px; flex-wrap:wrap; margin:20px 0; }}
  .stat-card {{ background:#1e1e2e; border-radius:8px; padding:15px 25px; text-align:center; min-width:100px; }}
  .stat-card .num {{ font-size:2em; font-weight:bold; }}
  .critico {{ color:#e74c3c; }} .alto {{ color:#e67e22; }}
  .medio {{ color:#f1c40f; }} .bajo {{ color:#2ecc71; }}
  table {{ width:100%; border-collapse:collapse; margin-top:15px; }}
  th {{ background:#1e1e2e; padding:10px; text-align:left; color:#81d4fa; }}
  td {{ padding:9px 10px; border-bottom:1px solid #333; vertical-align:top; }}
  tr:hover {{ background:#1e1e2e55; }}
  .info-grid {{ display:grid; grid-template-columns:repeat(auto-fill, minmax(220px,1fr)); gap:12px; margin:15px 0; }}
  .info-item {{ background:#1e1e2e; border-radius:6px; padding:12px; }}
  .info-item .label {{ color:#81d4fa; font-size:0.8em; text-transform:uppercase; }}
  .info-item .value {{ font-weight:bold; margin-top:4px; }}
  footer {{ color:#555; margin-top:40px; text-align:center; font-size:0.85em; }}
</style>
</head>
<body>
<div class="container">
  <h1>Scan Tool Manager (STM) — Reporte de Seguridad</h1>
  <div class="info-grid">
    <div class="info-item"><div class="label">Objetivo analizado</div><div class="value">{objetivo}</div></div>
    <div class="info-item"><div class="label">Fecha y hora</div><div class="value">{ts}</div></div>
    <div class="info-item"><div class="label">Pais detectado</div><div class="value">{ipinfo.get('country', 'N/A')} — {ipinfo.get('city', 'N/A')}</div></div>
    <div class="info-item"><div class="label">Organizacion</div><div class="value">{ipinfo.get('org', 'N/A')}</div></div>
  </div>
  <h2>Score Global de Riesgo</h2>
  <div class="score-box">{score} / 100</div>
  <span class="nivel-badge">{nivel_score}</span>
  <h2>Resumen de Alertas</h2>
  <div class="stats">
    <div class="stat-card"><div class="num critico">{correlacion.get('criticas',0)}</div>Criticas</div>
    <div class="stat-card"><div class="num alto">{correlacion.get('altas',0)}</div>Altas</div>
    <div class="stat-card"><div class="num medio">{correlacion.get('medias',0)}</div>Medias</div>
    <div class="stat-card"><div class="num bajo">{correlacion.get('bajas',0)}</div>Bajas</div>
    <div class="stat-card"><div class="num" style="color:#81d4fa">{correlacion.get('total_alertas',0)}</div>Total</div>
  </div>
  <h2>Detalle de Alertas</h2>
  <table>
    <tr><th>Nivel</th><th>Tipo</th><th>Descripcion</th><th>Recomendacion</th></tr>
    {filas_alertas if filas_alertas else '<tr><td colspan="4" style="text-align:center;color:#2ecc71;">Sin alertas detectadas</td></tr>'}
  </table>
  <h2>Reconocimiento de Red</h2>
  <div class="info-grid">
    <div class="info-item"><div class="label">Responde ping</div><div class="value">{'Si' if recon.get('responde_ping') else 'No'}</div></div>
    <div class="info-item"><div class="label">Puertos abiertos</div><div class="value">{puertos_str}</div></div>
    <div class="info-item"><div class="label">IPs resueltas</div><div class="value">{recon.get('ips_resueltas', 'N/A')}</div></div>
    <div class="info-item"><div class="label">Score de abuso AbuseIPDB</div><div class="value">{score_ab}%</div></div>
  </div>
  <footer>Generado por Scan Tool Manager (STM) | {ts}</footer>
</div>
</body>
</html>"""

    ruta = RESULTADOS_DIR / f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(html)
    return str(ruta)
