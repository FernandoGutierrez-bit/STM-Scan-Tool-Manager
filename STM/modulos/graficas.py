# Scan Tool Manager (STM)
# Integrantes: Gabriel Aguiñaga Ruiz, Fernando De Jesús Gutiérrez,
#              López Eliseo Ojeda Hernández, Eduardo Velazquez Zepeda,
#              Pablo Javier Mora Delgadillo

from pathlib import Path

BASE_DIR       = Path(__file__).parent.parent
RESULTADOS_DIR = BASE_DIR / "resultados"
RESULTADOS_DIR.mkdir(exist_ok=True)


# Grafica de barras ASCII
def grafica_barras_ascii(datos: dict, titulo: str = "Grafica") -> str:
    if not datos:
        return "Sin datos para graficar"

    max_val = max(datos.values()) if datos.values() else 1
    ancho   = 40
    lineas  = [f"\n{'='*52}", f"  {titulo}", f"{'='*52}"]

    for etiqueta, valor in datos.items():
        barra_len = int((valor / max_val) * ancho) if max_val > 0 else 0
        barra     = "█" * barra_len
        lineas.append(f"  {etiqueta:<12} | {barra:<40} {valor}")

    lineas.append("=" * 52)
    return "\n".join(lineas)


# Grafica de alertas ASCII
def grafica_alertas(correlacion: dict) -> str:
    datos = {
        "CRITICO": correlacion.get("criticas", 0),
        "ALTO":    correlacion.get("altas",    0),
        "MEDIO":   correlacion.get("medias",   0),
        "BAJO":    correlacion.get("bajas",    0),
    }
    return grafica_barras_ascii(datos, "STM — Distribucion de Alertas por Nivel de Riesgo")


# Grafica matplotlib
def generar_grafica_matplotlib(datos: dict, titulo: str, nombre_archivo: str) -> str:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        COLORES = {
            "CRITICO": "#e74c3c",
            "ALTO":    "#e67e22",
            "MEDIO":   "#f1c40f",
            "BAJO":    "#2ecc71",
            "INFO":    "#3498db",
        }

        etiquetas = list(datos.keys())
        valores   = list(datos.values())
        colores   = [COLORES.get(e, "#95a5a6") for e in etiquetas]

        fig, ax = plt.subplots(figsize=(10, 5))
        fig.patch.set_facecolor("#1e1e2e")
        ax.set_facecolor("#1e1e2e")

        bars = ax.bar(etiquetas, valores, color=colores, edgecolor="#333", linewidth=0.8, width=0.5)

        ax.set_title(titulo, fontsize=14, fontweight="bold", color="white", pad=15)
        ax.set_ylabel("Cantidad", color="#aaa")
        ax.set_xlabel("Nivel de Riesgo", color="#aaa")
        ax.tick_params(colors="white")
        ax.spines[:].set_color("#444")

        for bar, val in zip(bars, valores):
            ax.text(
                bar.get_x() + bar.get_width() / 2.,
                bar.get_height() + 0.05,
                str(val),
                ha="center", va="bottom",
                fontweight="bold", color="white", fontsize=12
            )

        plt.tight_layout()
        ruta = RESULTADOS_DIR / nombre_archivo
        plt.savefig(ruta, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        return str(ruta)

    except ImportError:
        return "matplotlib no instalado, ejecute: pip install matplotlib"
    except Exception as e:
        return f"Error generando grafica: {e}"


# Grafica de conexiones de red
def generar_grafica_conexiones(conexiones_por_estado: dict) -> str:
    return generar_grafica_matplotlib(
        conexiones_por_estado,
        "STM — Conexiones de Red por Estado",
        "grafica_conexiones.png"
    )
