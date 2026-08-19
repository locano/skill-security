#!/usr/bin/env python3
"""Genera el reporte HTML de seguridad desde los JSON del scan.

El HTML resultante tiene dos modos:
  - pantalla: sitio de revisión (índice lateral, filtros por severidad, búsqueda)
  - impresión: documento paginado A4 listo para PDF (Cmd+P)

El sistema visual se hereda de index.html (el landing del skill): mismo navy,
mismo acento, mismas familias tipográficas. La superficie se invierte a claro
porque el documento se lee largo y se imprime.
"""

import html as html_mod  # `html` es la variable del documento ensamblado
import json
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Falta PyYAML. Instalar con: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("security-reports")
CONFIG_PATH = OUT_DIR / "security.config.yml"


def load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_json(name):
    p = OUT_DIR / name
    if p.exists():
        try:
            with open(p) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
    return None


cfg = load_config()
project = cfg.get("project", {}) if cfg else {}
branding = cfg.get("branding", {}) if cfg else {}
REPORT = (cfg.get("report") or {}) if cfg else {}

PROJECT_NAME = project.get("name", "Proyecto")
BRANDING_ON = bool(branding.get("enabled", False))

# Paleta base heredada de index.html (landing). El navy va al chrome; el cuerpo
# del documento es claro porque se lee largo y se imprime.
COLOR_PRIMARY = branding.get("primary_color", "#0a1628") if BRANDING_ON else "#0a1628"
COLOR_SECONDARY = branding.get("secondary_color", "#091235") if BRANDING_ON else "#091235"
COLOR_ACCENT = branding.get("accent_color", "#6ca3ce") if BRANDING_ON else "#6ca3ce"
FONT_BODY = branding.get("font_family", "") if BRANDING_ON else ""
COMPANY_NAME = branding.get("company_name", "") if BRANDING_ON else ""

bandit = load_json("bandit-report.json")
npm_audit = load_json("npm-audit-report.json")
pip_audit = load_json("pip-audit-report.json")
zap = load_json("zap-dast-report.json")
zap_web = load_json("zap-dast-web.json")
zap_api = load_json("zap-dast-api.json")
sonar = load_json("sonarqube-summary.json")
sonar_issues = load_json("sonarqube-issues.json")
sonar_hotspots = load_json("sonarqube-hotspots.json")
sonar_status = load_json("sonar-status.json") or {}
prereqs = load_json("prereqs.json")
inventory = load_json("inventory.json") or {}
owasp = load_json("owasp-summary.json") or {}

# El plan de remediación es opcional. Distinguimos "no existe" de "existe pero
# está roto": lo segundo se avisa, porque si no un typo borra el trabajo manual.
REMEDIATION_PATH = OUT_DIR / "remediation-plan.json"
remediation = load_json("remediation-plan.json")
REMEDIATION_BROKEN = REMEDIATION_PATH.exists() and remediation is None

date_str = datetime.now().strftime("%d/%m/%Y")
zap_cfg = cfg.get("zap") or {}


# ----------------------------------------------------------------------------
# Primitivas. esc() se aplica en el productor (donde el JSON entra), nunca en el
# ensamblador: table() y callout() reciben HTML ya formado y no vuelven a escapar.
# ----------------------------------------------------------------------------

def esc(value, limit=None):
    """Escapa para HTML. Trunca ANTES de escapar para no cortar una entidad."""
    text = "" if value is None else str(value)
    if limit and len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return html_mod.escape(text, quote=True)


def slug(value):
    """'n/a' -> 'n-a', 'Medium (High)' -> 'medium-high'. Evita escapes en CSS."""
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-") or "na"


_SEV_MAP = {
    "critical": "crit", "crit": "crit", "critico": "crit", "crítico": "crit",
    "high": "high", "alto": "high", "error": "high", "fail": "high",
    "falla": "high", "hit": "high", "abierto": "high", "blocker": "crit",
    "medium": "med", "med": "med", "moderate": "med", "medio": "med",
    "major": "high",
    "parcial": "med", "minor": "low",
    "low": "low", "bajo": "low", "planificado": "low", "info": "low",
    "informational": "info", "informative": "info", "nd": "na",
    "ok": "ok", "pass": "ok", "clear": "ok", "cerrado": "ok", "closed": "ok",
    "n/a": "na", "na": "na", "aceptado": "na", "manual": "na", "none": "na",
}

_SEV_LABEL = {
    "crit": "Crítico", "high": "Alto", "med": "Medio",
    "low": "Bajo", "info": "Info", "ok": "OK", "na": "N/A",
}

# Orden de peor a mejor. Se usa para ordenar filas y para el peor-caso de un grupo.
_SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4, "ok": 5, "na": 6}


def sev_key(raw):
    """Normaliza cualquier token de severidad/estado a: crit|high|med|low|info|ok|na."""
    return _SEV_MAP.get(str(raw or "").strip().lower(), "na")


def sev_class(raw):
    return "s-" + sev_key(raw)


def pill(text, kind=None, title=None):
    cls = sev_class(kind if kind is not None else text)
    attr = f' title="{esc(title)}"' if title else ""
    return f'<span class="pill {cls}"{attr}>{esc(text)}</span>'


def table(headers, rows, empty_msg="Sin datos.", data_attrs=None):
    """Tabla con <thead> real: es lo que permite repetir el encabezado al imprimir.

    `rows` son listas de celdas ya renderizadas (HTML). `data_attrs` es una lista
    paralela de dicts que se vuelcan como atributos en cada <tr> — así el filtro
    por severidad y la búsqueda operan sin tocar el contenido.
    """
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    if not rows:
        body = f'<tr><td colspan="{len(headers)}" class="t-empty">{empty_msg}</td></tr>'
    else:
        parts = []
        for i, row in enumerate(rows):
            attrs = ""
            if data_attrs and i < len(data_attrs):
                attrs = "".join(f' data-{k}="{esc(v)}"' for k, v in data_attrs[i].items())
            cells = "".join(f"<td>{c}</td>" for c in row)
            parts.append(f"<tr{attrs}>{cells}</tr>")
        body = "".join(parts)
    return (
        '<div class="t-wrap"><table class="t-light">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody>"
        "</table></div>"
    )


def callout(body_html, kind="info", title=None):
    """Fondo tintado + borde 1px. Sin barra lateral gruesa."""
    head = f'<p class="c-title">{esc(title)}</p>' if title else ""
    return f'<div class="callout k-{esc(kind)}">{head}{body_html}</div>'


def code_block(text, label=None):
    cap = f"<figcaption>{esc(label)}</figcaption>" if label else ""
    return f'<figure class="code">{cap}<pre><code>{esc(text)}</code></pre></figure>'


def kv_grid(pairs):
    """Grilla de metadatos. Omite pares vacíos: sin filas con '—' de relleno."""
    items = [(k, v) for k, v in pairs if v]
    if not items:
        return ""
    cells = "".join(
        f'<div class="kv"><dt>{esc(k)}</dt><dd>{v}</dd></div>' for k, v in items
    )
    cls = "meta-grid" + (" is-narrow" if len(items) <= 2 else "")
    return f'<dl class="{cls}">{cells}</dl>'


# Iconos dibujados, un solo grosor de trazo. Nada de emoji como sistema de iconos.
_ICONS = {
    "shield": '<path d="M12 3 4 6v6c0 4.4 3.4 7.6 8 9 4.6-1.4 8-4.6 8-9V6l-8-3Z"/>',
    "alert": '<path d="M12 9v4m0 4h.01M10.3 4.3 2.6 17.6a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0Z"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    "info": '<path d="M12 16v-5m0-3h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/>',
    "print": '<path d="M6 9V3h12v6M6 18H4v-6h16v6h-2M8 14h8v7H8v-7Z"/>',
    "search": '<path d="m21 21-4.3-4.3M17 11a6 6 0 1 1-12 0 6 6 0 0 1 12 0Z"/>',
    "link": '<path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1m-2-9a5 5 0 0 1 7 0l3-3a5 5 0 0 0-7-7l-1 1"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>',
}


def icon(name, cls="ico"):
    path = _ICONS.get(name)
    if not path:
        return ""
    return (
        f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" '
        f'aria-hidden="true">{path}</svg>'
    )


# ----------------------------------------------------------------------------
# Tokens y CSS. BASE_CSS es un string PLANO (no f-string): llaves simples, cero
# doblado. Los tokens se inyectan por css_root(), que arma el :root sin llaves
# literales dentro de una f-string.
# ----------------------------------------------------------------------------

_FALLBACK_SANS = 'system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'

TOKENS = {
    # Chrome: navy del landing.
    "navy-1": "#020617",
    "navy-2": COLOR_PRIMARY,
    "navy-3": COLOR_SECONDARY,
    "accent": COLOR_ACCENT,
    "accent-dim": "#4d7a9e",
    "accent-soft": "rgba(108,163,206,.14)",
    # Documento: superficie clara.
    "paper": "#ffffff",
    "paper-2": "#f7f9fb",
    "ink": "#141821",
    "ink-2": "#4a5462",
    # Gris atenuado que todavía pasa AA (4.9:1 sobre paper-2). Se usa donde antes
    # había opacity, que rompía el contraste.
    "muted-strong": "#646e7b",
    "line": "#e2e7ed",
    "line-2": "#cdd5df",
    # Severidad, derivada de los matices del landing para fondo claro.
    "crit": "#8c1d18", "crit-bg": "#fdeceb", "crit-line": "#f3c9c5",
    "high": "#7c4a03", "high-bg": "#fdf1dc", "high-line": "#f0cf9d",
    "med": "#6b5600", "med-bg": "#fdf8dc", "med-line": "#e8d98f",
    "low": "#1a4b8c", "low-bg": "#e9f1fd", "low-line": "#bcd4f7",
    "info": "#3d4550", "info-bg": "#f2f4f7", "info-line": "#d7dce3",
    "ok": "#14532d", "ok-bg": "#e7f6ec", "ok-line": "#b3ddc2",
    "na": "#4b5563", "na-bg": "#f3f4f6", "na-line": "#d8dce2",
    # Tipografía. Poppins/Montserrat vienen del landing por Google Fonts; el
    # fallback completo mantiene las métricas si el archivo se abre sin red.
    "font-display": (FONT_BODY or '"Poppins", ' + _FALLBACK_SANS),
    "font-body": (FONT_BODY or '"Montserrat", ' + _FALLBACK_SANS),
    "font-mono": 'ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace',
    "measure": "72ch",
    "sidebar-w": "17rem",
    "ease": "cubic-bezier(.22,1,.36,1)",
}


def css_root():
    return ":root{" + "".join(f"--{k}:{v};" for k, v in TOKENS.items()) + "}"


BASE_CSS = """
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;font-family:var(--font-body);color:var(--ink);background:var(--paper);
  line-height:1.65;font-size:16px;-webkit-font-smoothing:antialiased;
}

/* Superficies del navegador: son parte del diseño, no defaults heredados. */
::selection{background:var(--accent-soft);color:var(--navy-2)}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:3px}
a{color:var(--accent-dim);text-underline-offset:.18em;text-decoration-thickness:1px}
a:hover{color:var(--navy-3)}
input{caret-color:var(--accent-dim)}
.t-wrap{scrollbar-width:thin;scrollbar-color:var(--line-2) transparent}
.t-wrap::-webkit-scrollbar{height:9px}
.t-wrap::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:9px}
.t-wrap::-webkit-scrollbar-track{background:transparent}

h1,h2,h3{font-family:var(--font-display);margin:0;text-wrap:balance;letter-spacing:-.015em}
p{margin:0 0 .9rem;text-wrap:pretty}
p:last-child{margin-bottom:0}
code,kbd,pre,.mono{font-family:var(--font-mono);font-variant-ligatures:none}
:not(pre)>code{
  font-size:.86em;background:var(--paper-2);border:1px solid var(--line);
  border-radius:4px;padding:.08em .34em;color:var(--navy-3);
}

/* --- Layout ------------------------------------------------------------- */
.shell{display:grid;grid-template-columns:var(--sidebar-w) minmax(0,1fr)}
.side{
  grid-column:1;position:sticky;top:0;height:100vh;overflow-y:auto;
  background:linear-gradient(170deg,var(--navy-2),var(--navy-1));
  color:#e8eef6;padding:1.6rem 1.1rem 2rem;
}
.side-brand{font-family:var(--font-display);font-weight:600;font-size:.95rem;
  color:#fff;display:flex;align-items:center;gap:.5rem;margin-bottom:.25rem}
.side-brand .ico{width:18px;height:18px;color:var(--accent)}
.side-proj{font-size:.78rem;color:#9fb2c9;margin:0 0 1.5rem;word-break:break-word}
.side nav{display:flex;flex-direction:column;gap:.1rem}
.side nav a{
  display:flex;gap:.6rem;padding:.42rem .6rem;border-radius:6px;font-size:.83rem;
  color:#b6c6d9;text-decoration:none;transition:background .2s var(--ease),color .2s var(--ease);
}
.side nav a .n{color:#63788f;font-variant-numeric:tabular-nums;min-width:1.1rem}
.side nav a:hover{background:rgba(255,255,255,.06);color:#fff}
.side nav a.is-active{background:var(--accent-soft);color:#fff}
.side nav a.is-active .n{color:var(--accent)}
.side-foot{margin-top:1.8rem;padding-top:1rem;border-top:1px solid rgba(255,255,255,.1);
  font-size:.72rem;color:#7c8ea6;line-height:1.5}

.main{grid-column:2;min-width:0}
.wrap{max-width:60rem;margin:0 auto;padding:0 clamp(1.2rem,4vw,3rem)}

/* --- Masthead ----------------------------------------------------------- */
.masthead{background:var(--navy-2);color:#dce6f2;padding:.85rem 0}
.masthead .wrap{display:flex;flex-wrap:wrap;gap:.4rem 1.5rem;
  align-items:baseline;justify-content:space-between}
.masthead .m-type{font-family:var(--font-display);font-weight:600;font-size:.9rem;color:#fff}
.masthead .m-class{font-size:.76rem;color:#95a9c1;font-variant-numeric:tabular-nums}

.head{padding:2.6rem 0 1.4rem}
h1{font-size:clamp(1.85rem,3.6vw,2.7rem);line-height:1.14;color:var(--navy-2);font-weight:700}
.h-status{margin-top:1rem;display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
.doc-pill{
  display:inline-flex;align-items:center;gap:.45rem;padding:.32rem .8rem;
  border:1px solid var(--line-2);border-radius:999px;font-size:.82rem;
  color:var(--ink-2);background:var(--paper-2);font-variant-numeric:tabular-nums;
}
.doc-pill .ico{width:15px;height:15px;color:var(--ok)}

/* Cobertura: qué corrió y cuánto encontró. Es dato, no etiqueta decorativa. */
.coverage{display:flex;flex-wrap:wrap;gap:.5rem;margin:1.5rem 0 0;padding:0;list-style:none}
.cov{
  display:flex;align-items:baseline;gap:.45rem;padding:.4rem .7rem;border-radius:7px;
  border:1px solid var(--line);background:var(--paper-2);font-size:.8rem;
}
.cov b{font-family:var(--font-display);font-weight:600;color:var(--navy-3);letter-spacing:.01em}
.cov span{color:var(--ink-2);font-variant-numeric:tabular-nums}
/* "no ejecutado" es información, no ruido: se atenúa con color y no con
   opacity, que lo dejaba en 2.87:1 — por debajo del piso de legibilidad. */
.cov.is-off{background:transparent;border-style:dashed}
.cov.is-off b{color:var(--muted-strong)}
.cov.is-off span{color:var(--muted-strong);font-style:italic}

.meta-grid{
  display:grid;grid-template-columns:repeat(2,minmax(0,1fr));
  gap:1.1rem 2.5rem;margin:2rem 0 0;padding:1.5rem 0 0;border-top:1px solid var(--line);
}
.meta-grid.is-narrow{grid-template-columns:minmax(0,1fr)}
.kv dt{font-size:.73rem;text-transform:uppercase;letter-spacing:.07em;color:var(--ink-2);
  margin-bottom:.18rem}
.kv dd{margin:0;font-size:.92rem;color:var(--ink);word-break:break-word}

/* --- Toolbar (solo pantalla) -------------------------------------------- */
.toolbar{
  position:sticky;top:0;z-index:20;background:rgba(255,255,255,.94);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--line);
  box-shadow:0 1px 3px rgba(20,24,33,.05),0 8px 24px -12px rgba(20,24,33,.14);
  margin-top:2.5rem;
}
.toolbar .wrap{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;padding-block:.65rem}
.filters{display:flex;flex-wrap:wrap;gap:.35rem;margin:0;padding:0;list-style:none}
.f-btn{
  display:inline-flex;align-items:baseline;gap:.4rem;padding:.3rem .65rem;border-radius:999px;
  border:1px solid var(--line-2);background:var(--paper);font:inherit;font-size:.79rem;
  color:var(--ink-2);cursor:pointer;transition:border-color .18s var(--ease),background .18s var(--ease);
}
.f-btn b{font-variant-numeric:tabular-nums;font-weight:600}
.f-btn:hover{border-color:var(--accent)}
.f-btn[aria-pressed="true"]{background:var(--navy-2);border-color:var(--navy-2);color:#fff}
.f-btn[data-sev="crit"] b{color:var(--crit)}
.f-btn[data-sev="high"] b{color:var(--high)}
.f-btn[data-sev="med"] b{color:var(--med)}
.f-btn[data-sev="low"] b{color:var(--low)}
.f-btn[aria-pressed="true"] b{color:#fff}
.t-search{position:relative;margin-left:auto;display:flex;align-items:center}
.t-search .ico{position:absolute;left:.6rem;width:15px;height:15px;color:var(--ink-2);
  pointer-events:none}
.t-search input{
  font:inherit;font-size:.82rem;padding:.36rem .7rem .36rem 1.9rem;border-radius:999px;
  border:1px solid var(--line-2);background:var(--paper);color:var(--ink);width:15.5rem;
}
.t-search input::placeholder{color:var(--ink-2)}
.btn-print{
  display:inline-flex;align-items:center;gap:.4rem;padding:.36rem .8rem;border-radius:7px;
  border:1px solid var(--navy-2);background:var(--navy-2);color:#fff;font:inherit;
  font-size:.8rem;cursor:pointer;transition:background .18s var(--ease);
}
.btn-print:hover{background:var(--navy-3)}
.btn-print .ico{width:15px;height:15px}

/* --- Secciones ---------------------------------------------------------- */
.sec{padding:2.6rem 0 0;scroll-margin-top:4.5rem}
.sec>summary{
  list-style:none;cursor:pointer;display:flex;align-items:baseline;gap:.7rem;
  padding-bottom:.7rem;border-bottom:2px solid var(--accent);
}
.sec>summary::-webkit-details-marker{display:none}
.sec>summary::after{
  content:"";margin-left:auto;width:8px;height:8px;border-right:1.5px solid var(--ink-2);
  border-bottom:1.5px solid var(--ink-2);transform:rotate(45deg) translateY(-2px);
  transition:transform .22s var(--ease);
}
.sec[open]>summary::after{transform:rotate(-135deg) translateY(-2px)}
.sec h2{font-size:clamp(1.15rem,2vw,1.45rem);color:var(--navy-2);font-weight:600}
.sec .s-num{font-family:var(--font-display);font-size:.9rem;color:var(--accent-dim);
  font-variant-numeric:tabular-nums;font-weight:600}
.sec-body{padding-top:1.3rem}
.sec-body>*+*{margin-top:1.1rem}
h3{font-size:1rem;color:var(--navy-3);font-weight:600;margin-top:1.8rem}
h3 .s-num{font-size:.85rem}
.prose{max-width:var(--measure)}

/* --- Tablas ------------------------------------------------------------- */
.t-wrap{overflow-x:auto;margin:0}
table.t-light{border-collapse:collapse;width:100%;font-size:.845rem}
.t-light th{
  text-align:left;font-family:var(--font-body);font-weight:600;font-size:.7rem;
  text-transform:uppercase;letter-spacing:.07em;color:var(--ink-2);
  padding:0 .8rem .5rem 0;border-bottom:1px solid var(--line-2);white-space:nowrap;
}
.t-light td{
  padding:.6rem .8rem .6rem 0;border-bottom:1px solid var(--line);vertical-align:top;
  overflow-wrap:break-word;
}
.t-light tr:last-child td{border-bottom:none}
.t-light td:last-child,.t-light th:last-child{padding-right:0}
.t-light td:first-child{min-width:9rem}
.t-light .num{font-variant-numeric:tabular-nums;white-space:nowrap}
.t-light .t-empty{color:var(--ink-2);font-style:italic;padding:.9rem 0}
/* Solo las rutas y reglas parten en cualquier punto: son tokens sin espacios. */
.t-light .loc{font-family:var(--font-mono);font-size:.8rem;color:var(--navy-3);
  overflow-wrap:anywhere}
tr.is-dim{opacity:.28}
tr.is-hidden{display:none}

/* --- Pills -------------------------------------------------------------- */
.pill{
  display:inline-block;padding:.12rem .5rem;border-radius:5px;font-size:.72rem;
  font-weight:600;white-space:nowrap;border:1px solid;letter-spacing:.01em;
}
.s-crit{color:var(--crit);background:var(--crit-bg);border-color:var(--crit-line)}
.s-high{color:var(--high);background:var(--high-bg);border-color:var(--high-line)}
.s-med{color:var(--med);background:var(--med-bg);border-color:var(--med-line)}
.s-low{color:var(--low);background:var(--low-bg);border-color:var(--low-line)}
.s-info{color:var(--info);background:var(--info-bg);border-color:var(--info-line)}
.s-ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-line)}
.s-na{color:var(--na);background:var(--na-bg);border-color:var(--na-line)}

/* --- Callouts: fondo tintado + borde 1px, sin barra lateral gruesa ------ */
.callout{padding:.95rem 1.1rem;border-radius:8px;border:1px solid;font-size:.875rem}
.callout>*+*{margin-top:.6rem}
.callout .c-title{font-family:var(--font-display);font-weight:600;font-size:.83rem;
  letter-spacing:.01em;margin:0 0 .35rem}
.callout ul{margin:.4rem 0 0;padding-left:1.1rem}
.callout li+li{margin-top:.2rem}
.k-info{background:var(--low-bg);border-color:var(--low-line);color:#173e70}
.k-info .c-title{color:var(--low)}
.k-warn{background:var(--high-bg);border-color:var(--high-line);color:#6b4103}
.k-warn .c-title{color:var(--high)}
.k-ok{background:var(--ok-bg);border-color:var(--ok-line);color:#11492a}
.k-ok .c-title{color:var(--ok)}
.k-neutral{background:var(--paper-2);border-color:var(--line);color:var(--ink-2)}
.k-neutral .c-title{color:var(--navy-3)}
.callout code{background:rgba(255,255,255,.6)}

/* --- Código ------------------------------------------------------------- */
figure.code{margin:0;border:1px solid var(--line);border-radius:8px;overflow:hidden;
  background:var(--navy-1)}
figure.code figcaption{
  font-family:var(--font-body);font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;
  color:#8fa3bd;padding:.5rem .9rem;background:var(--navy-2);
  border-bottom:1px solid rgba(255,255,255,.08);
}
figure.code pre{margin:0;padding:.9rem;overflow-x:auto;font-size:.8rem;line-height:1.6}
figure.code code{color:#dbe6f3}
.code-pair{display:grid;gap:.7rem;margin-top:.9rem}
@media (min-width:52rem){.code-pair{grid-template-columns:1fr 1fr}}


/* --- Pestañas ----------------------------------------------------------- */
.tabbar{
  display:flex;flex-wrap:wrap;gap:.25rem;margin:2rem 0 0;
  border-bottom:1px solid var(--line);
}
.tab-btn{
  font:inherit;font-family:var(--font-display);font-size:.87rem;font-weight:600;
  padding:.6rem .95rem;border:none;background:none;color:var(--ink-2);cursor:pointer;
  border-bottom:2px solid transparent;margin-bottom:-1px;border-radius:6px 6px 0 0;
  transition:color .18s var(--ease),border-color .18s var(--ease),background .18s var(--ease);
}
.tab-btn:hover{color:var(--navy-2);background:var(--paper-2)}
.tab-btn[aria-selected="true"]{color:var(--navy-2);border-bottom-color:var(--accent)}
.tab-panel{padding-top:1.8rem;scroll-margin-top:4.5rem}
/* Solo se oculta si el JS pudo marcar el documento: sin JS, todo visible. */
.js-on .tab-panel{display:none}
.js-on .tab-panel.is-active{display:block}
.js-on .tab-panel+.tab-panel{border-top:none}
:root:not(.js-on) .tab-panel+.tab-panel{
  margin-top:2.5rem;padding-top:2rem;border-top:1px solid var(--line);
}
.tab-panel>*+*{margin-top:1.1rem}
.panel-h{
  font-size:clamp(1.3rem,2.2vw,1.7rem);color:var(--navy-2);font-weight:700;
  padding-bottom:.6rem;border-bottom:2px solid var(--accent);margin-bottom:1.4rem;
}
h4{font-family:var(--font-display);font-size:.95rem;color:var(--navy-3);font-weight:600;
  margin:1.6rem 0 .7rem;display:flex;flex-wrap:wrap;gap:.5rem;align-items:baseline}
h4 .loc{font-family:var(--font-mono);font-size:.78rem;color:var(--ink-2);font-weight:400}
.sub-lbl{font-family:var(--font-display);font-weight:600;font-size:.82rem;color:var(--ink-2);
  margin:1.2rem 0 .4rem;text-transform:uppercase;letter-spacing:.05em}
.more-note{font-size:.8rem;color:var(--ink-2);font-style:italic;margin-top:.5rem}
.two-col{display:grid;gap:1rem}
@media (min-width:48rem){.two-col{grid-template-columns:1fr 1fr}}
details.fold{border:1px solid var(--line);border-radius:8px;background:var(--paper-2)}
details.fold>summary{cursor:pointer;padding:.75rem 1rem;font-family:var(--font-display);
  font-weight:600;font-size:.85rem;color:var(--navy-3);list-style:none;display:flex;
  align-items:center;gap:.5rem}
details.fold>summary::-webkit-details-marker{display:none}
details.fold>summary::after{content:"";margin-left:auto;width:7px;height:7px;
  border-right:1.5px solid var(--ink-2);border-bottom:1.5px solid var(--ink-2);
  transform:rotate(45deg) translateY(-2px);transition:transform .22s var(--ease)}
details.fold[open]>summary::after{transform:rotate(-135deg) translateY(-2px)}
details.fold>*:not(summary){padding:0 1rem 1rem}

/* --- Footer ------------------------------------------------------------- */
.foot{margin-top:3.5rem;padding:1.5rem 0 3rem;border-top:1px solid var(--line);
  font-size:.76rem;color:var(--ink-2)}
.foot .wrap{display:flex;flex-wrap:wrap;gap:.3rem 1.4rem}
.foot b{font-weight:600;color:var(--navy-3)}

/* El índice móvil solo existe cuando el sidebar desaparece. */
.toc-m{display:none}
@media (max-width:60rem){
  .shell{grid-template-columns:minmax(0,1fr)}
  .side{display:none}
  .main{grid-column:1}
  .meta-grid{grid-template-columns:minmax(0,1fr)}
  .t-search{margin-left:0;width:100%}
  .t-search input{width:100%}
  .toc-m{display:block;margin:1.5rem 0 0;border:1px solid var(--line);
    border-radius:8px;background:var(--paper-2)}
  .toc-m>summary{cursor:pointer;padding:.7rem .9rem;font-family:var(--font-display);
    font-weight:600;font-size:.85rem;color:var(--navy-2);list-style:none;
    display:flex;align-items:center;gap:.5rem}
  .toc-m>summary::-webkit-details-marker{display:none}
  .toc-m>summary::after{content:"";margin-left:auto;width:7px;height:7px;
    border-right:1.5px solid var(--ink-2);border-bottom:1.5px solid var(--ink-2);
    transform:rotate(45deg) translateY(-2px);transition:transform .22s var(--ease)}
  .toc-m[open]>summary::after{transform:rotate(-135deg) translateY(-2px)}
  .toc-m .ico{width:16px;height:16px;color:var(--accent-dim)}
  .toc-m nav{display:flex;flex-direction:column;padding:0 .5rem .6rem}
  .toc-m nav a{display:flex;gap:.6rem;padding:.4rem .5rem;border-radius:6px;
    font-size:.85rem;color:var(--ink);text-decoration:none}
  .toc-m nav a .n{color:var(--accent-dim);font-variant-numeric:tabular-nums;
    min-width:1.2rem;font-weight:600}
  .toc-m nav a:hover{background:var(--accent-soft)}
}
@media (prefers-reduced-motion:reduce){
  *{animation-duration:.01ms !important;transition-duration:.01ms !important}
}

/* --- Impresión: el documento paginado ----------------------------------- */
@page{size:A4;margin:16mm 14mm 18mm}
@media print{
  html,body{-webkit-print-color-adjust:exact;print-color-adjust:exact;background:#fff}
  body{font-size:10pt;line-height:1.5}
  .side,.toolbar,.no-print{display:none !important}
  .shell{display:block}
  .main{grid-column:1}
  .wrap{max-width:none;padding:0}
  .masthead{padding:.6rem 0;margin-bottom:.4rem}
  .head{padding:1.2rem 0 .8rem}
  h1{font-size:20pt}
  .sec{padding-top:1.1rem;break-inside:auto}
  .sec>summary::after{display:none}
  .sec>summary{cursor:auto}
  details{display:block}
  details>summary{display:flex}
  .sec h2{font-size:13pt}
  h3{font-size:11pt;margin-top:1rem}
  h2,h3,.sec>summary{break-after:avoid-page}
  tr,figure.code,.callout,.meta-grid,.kv,.cov{break-inside:avoid}
  thead{display:table-header-group}
  .t-wrap{overflow:visible}
  table.t-light{font-size:8.6pt}
  figure.code pre{font-size:8pt;white-space:pre-wrap}
  a{color:inherit;text-decoration:none}
  .toc-print a::after{content:"";}
  .foot{margin-top:1.5rem;padding-bottom:0}
  tr.is-dim,tr.is-hidden{opacity:1 !important;display:table-row !important}
  /* En papel no se hace clic: todas las pestañas visibles, una por página. */
  .tabbar{display:none !important}
  .tab-panel,.js-on .tab-panel{display:block !important;padding-top:0}
  .tab-panel[hidden]{display:block !important}
  .tab-panel+.tab-panel{break-before:page}
  .panel-h{break-after:avoid-page}
  details.fold{border:none;background:none}
  details.fold>summary{display:none}
  details.fold>*:not(summary){padding:0}

}
"""


# ----------------------------------------------------------------------------
# Secciones. Los números salen de un único enumerate(), así el índice lateral y
# los encabezados no pueden desincronizarse, y agregar una sección es una línea.
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Normalización de hallazgos. Todo sale de los JSON que ya están en disco: los
# scanners no cambian. Cada productor tolera que su archivo no exista.
# ----------------------------------------------------------------------------

def classify_priority(sev, source="", kind=""):
    """P1 significa "actuar ya por seguridad", no "la herramienta gritó fuerte".

    La severidad cruda no alcanza: un BUG MAJOR de Sonar es un defecto de
    correctitud, no una vulnerabilidad, y tratarlo como P1 ahoga a los que sí lo
    son. Un CVE conocido con fix disponible, en cambio, sí es urgente.
    """
    key = sev_key(sev)

    if source == "sonar" and kind == "bug":
        # Importan, pero son correctitud. Nunca desplazan a un hallazgo de seguridad.
        return "P2" if key in ("crit", "high") else "P3"

    if source == "sonar" and kind == "vuln":
        # BLOCKER/CRITICAL son secretos y fallas reales; MAJOR suele ser
        # hardening de infraestructura (límites de recursos, políticas k8s).
        if key == "crit":
            return "P1"
        return "P2" if key == "high" else "P3"

    if key in ("crit", "high"):
        return "P1"
    if key == "med":
        return "P2"
    return "P3"


def _finding(fid, source, title, location, severity, detail="", cwe=None, rule="",
             kind="", priority=None):
    return {
        "id": fid, "source": source, "title": title, "location": location,
        "severity": sev_key(severity), "detail": detail, "cwe": cwe, "rule": rule,
        "kind": kind,
        "priority": priority or classify_priority(severity, source, kind),
    }


def bandit_findings():
    if not bandit:
        return []
    out = []
    for r in bandit.get("results", []):
        cwe = r.get("issue_cwe")
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else cwe
        fname, line = r.get("filename", ""), r.get("line_number", "")
        out.append(_finding(
            f"bandit:{r.get('test_id','')}:{fname}:{line}", "bandit",
            r.get("test_name") or r.get("test_id", "") or "Hallazgo Bandit",
            f"{fname}:{line}", r.get("issue_severity", "LOW"),
            r.get("issue_text", ""), cwe_id, r.get("test_id", ""),
        ))
    return out


def sca_node_entries():
    """Normaliza el audit de Node, que viene en dos formatos incompatibles.

    npm  -> {"vulnerabilities": {paquete: {severity, via, range, fixAvailable}}}
    pnpm -> {"advisories":      {id:      {module_name, severity, title, url, …}}}

    Leer solo el primero hacía que un proyecto pnpm reportara 0 vulnerabilidades
    teniendo cientos. Devuelve (entradas, formato, totales_metadata).
    """
    if not npm_audit:
        return [], "", {}

    meta = ((npm_audit.get("metadata") or {}).get("vulnerabilities") or {}) \
        if isinstance(npm_audit.get("metadata"), dict) else {}

    entries = []
    vulns = npm_audit.get("vulnerabilities") or {}
    if vulns:
        for name, v in vulns.items():
            via = v.get("via") or []
            titles = [x.get("title", "") for x in via if isinstance(x, dict)]
            entries.append({
                "id": f"npm:{name}",
                "package": name,
                "severity": v.get("severity", "low"),
                "title": "; ".join(t for t in titles if t)[:160],
                "range": v.get("range", ""),
                "fix": bool(v.get("fixAvailable")),
                "patched": "",
                "url": "",
                "cves": [],
                "paths": [],
            })
        return entries, "npm", meta

    advisories = npm_audit.get("advisories") or {}
    if advisories:
        for aid, a in advisories.items():
            mod = a.get("module_name", "")
            paths = []
            for f in (a.get("findings") or [])[:3]:
                paths.extend((f.get("paths") or [])[:2])
            entries.append({
                "id": f"pnpm:{mod}:{aid}",
                "package": mod,
                "severity": a.get("severity", "low"),
                "title": a.get("title", ""),
                "range": a.get("vulnerable_versions", ""),
                "fix": bool(a.get("patched_versions")
                            and a.get("patched_versions") != "<0.0.0"),
                "patched": a.get("patched_versions", ""),
                "url": a.get("url", ""),
                "cves": a.get("cves") or [],
                "paths": paths,
            })
        return entries, "pnpm", meta

    return [], ("vacío" if meta else ""), meta


def npm_findings():
    entries, _fmt, meta = sca_node_entries()
    out = []
    for e in entries:
        detail = e["title"] or ("Fix disponible" if e["fix"] else "Sin fix disponible")
        if e["range"]:
            detail += f" · afecta {e['range']}"
        if e["patched"]:
            detail += f" · corregido en {e['patched']}"
        out.append(_finding(
            e["id"], "npm", e["package"], "dependencias",
            e["severity"], detail,
        ))
    if out or not meta:
        return out

    # El detalle vino vacío pero el metadata dice que hay vulnerabilidades:
    # emitir una fila por severidad antes que reportar cero, que sería mentir.
    for sev in ("critical", "high", "moderate", "low"):
        n = meta.get(sev) or 0
        if n:
            out.append(_finding(
                f"npm:agregado:{sev}", "npm", f"{n} dependencia(s) {sev}",
                "dependencias", sev,
                "El audit no devolvió el detalle por paquete; solo el total.",
            ))
    return out


def pip_findings():
    if not pip_audit:
        return []
    deps = pip_audit.get("dependencies") if isinstance(pip_audit, dict) else pip_audit
    out = []
    for dep in deps or []:
        if not isinstance(dep, dict):
            continue
        name, ver = dep.get("name", ""), dep.get("version", "")
        for v in dep.get("vulns", []) or []:
            fixes = v.get("fix_versions") or []
            out.append(_finding(
                f"pip:{name}:{v.get('id','')}", "pip",
                f"{name} {ver} — {v.get('id','')}", "requirements",
                "med" if fixes else "low",
                v.get("description", "") or ("Fix: " + ", ".join(fixes) if fixes else ""),
            ))
    return out


def zap_findings():
    out = []
    for doc, scope in ((zap, "single"), (zap_web, "web"), (zap_api, "api")):
        if not doc:
            continue
        for alert in iter_zap_alerts(doc):
            risk = (alert.get("riskdesc") or "Informational").split(" ")[0]
            plugin = alert.get("pluginid") or slug(alert.get("name", ""))
            inst = alert.get("instances") or []
            loc = inst[0].get("uri", "") if inst else (zap_cfg.get(f"{scope}_url") or "")
            out.append(_finding(
                f"zap:{scope}:{plugin}", "zap", alert.get("name", ""), loc, risk,
                alert.get("desc", ""), alert.get("cweid"),
            ))
    return out


def sonar_issue_list():
    """Los issues crudos, partidos por tipo.

    SonarQube usa `severity` para impacto de MANTENIBILIDAD, no de seguridad: un
    `CRITICAL` puede ser un ternario anidado. Mezclarlos ahogaba los hallazgos
    reales, así que el tipo manda sobre la severidad.
    """
    raw = sonar_issues if isinstance(sonar_issues, list) else (
        (sonar_issues or {}).get("issues") if isinstance(sonar_issues, dict) else None
    )
    buckets = {"VULNERABILITY": [], "BUG": [], "CODE_SMELL": []}
    for it in raw or []:
        buckets.setdefault(it.get("type") or "CODE_SMELL", []).append(it)
    return buckets


def _sonar_row(it, kind):
    comp = (it.get("component") or "").split(":")[-1]
    line = it.get("line")
    return _finding(
        f"sonar:{it.get('key') or it.get('rule','')}", "sonar",
        it.get("rule", "") or f"Issue SonarQube ({kind})",
        f"{comp}:{line}" if line else comp,
        it.get("severity", "INFO"), it.get("message", ""),
        rule=it.get("rule", ""), kind=kind,
    )


def sonar_findings():
    """Solo lo que es seguridad o defecto alimenta el plan y los contadores.

    Los code smells se muestran en su propio bloque, pero no se cuentan como
    hallazgos de seguridad: son deuda técnica.
    """
    out = []
    buckets = sonar_issue_list()
    for it in buckets.get("VULNERABILITY") or []:
        out.append(_sonar_row(it, "vuln"))
    for it in buckets.get("BUG") or []:
        out.append(_sonar_row(it, "bug"))

    hotspots = sonar_hotspots if isinstance(sonar_hotspots, list) else (
        (sonar_hotspots or {}).get("hotspots") if isinstance(sonar_hotspots, dict) else None
    )
    for hs in hotspots or []:
        comp = (hs.get("component") or "").split(":")[-1]
        line = hs.get("line")
        out.append(_finding(
            f"sonar:hotspot:{hs.get('key','')}", "sonar",
            hs.get("securityCategory", "") or "Security hotspot",
            f"{comp}:{line}" if line else comp,
            hs.get("vulnerabilityProbability", "MEDIUM"), hs.get("message", ""),
        ))

    if out or not sonar:
        return out
    # Sin export de detalle: una fila por métrica no vacía, para no perder la señal.
    for key, label, sev in (
        ("vulnerabilities", "Vulnerabilidades", "high"),
        ("bugs", "Bugs", "med"),
        ("security_hotspots", "Security hotspots", "med"),
    ):
        n = sonar.get(key) or 0
        if n:
            out.append(_finding(
                f"sonar:{key}", "sonar", f"{label}: {n}", "proyecto", sev,
                "Detalle solo en el dashboard. Exportá sonarqube-issues.json "
                "para consultarlo sin el contenedor.",
            ))
    if str(sonar.get("quality_gate", "")).upper() == "ERROR":
        out.append(_finding(
            "sonar:quality_gate", "sonar", "Quality gate en ERROR", "proyecto", "high",
        ))
    return out


def owasp_findings():
    out = []
    for scope in ("web", "api"):
        for row in owasp.get(scope) or []:
            rev = row.get("review") or {}
            if row.get("status") != "hit" and rev.get("status") != "fail":
                continue
            risks = [sev_key(f.get("risk")) for f in (row.get("findings") or [])]
            worst = min(risks, key=lambda k: _SEV_RANK.get(k, 9)) if risks else "med"
            out.append(_finding(
                f"owasp:{row.get('id','')}", "owasp",
                f"{row.get('id','')} {row.get('name','')}",
                "revisión OWASP", worst,
                rev.get("evidence", "") or "Detectado por herramientas.",
            ))
    return out


def all_findings():
    rows = (bandit_findings() + npm_findings() + pip_findings()
            + zap_findings() + sonar_findings() + owasp_findings())
    rows.sort(key=lambda r: (_SEV_RANK.get(r["severity"], 9), r["source"], r["id"]))
    return rows


# ----------------------------------------------------------------------------
# Plan de remediación: auto por severidad, enriquecido por remediation-plan.json.
# ----------------------------------------------------------------------------

def _matches(row, pred):
    for key, want in (pred or {}).items():
        if key == "file":
            if str(want) not in (row.get("location") or ""):
                return False
        elif key == "severity":
            if sev_key(want) != row.get("severity"):
                return False
        elif key == "cwe":
            if str(want) != str(row.get("cwe")):
                return False
        elif key == "rule":
            if str(want).lower() not in str(row.get("rule", "")).lower():
                return False
        elif str(row.get(key, "")).lower() != str(want).lower():
            return False
    return True


def merge_remediation(findings, plan):
    """Devuelve (filas, huérfanos). Un id del plan que no matchea no se descarta
    en silencio: se muestra aparte, porque si no un re-scan que cambia ids borra
    el trabajo manual sin avisar."""
    plan = plan if isinstance(plan, dict) else {}
    rows = [dict(f) for f in findings]
    for r in rows:
        r.setdefault("status", "abierto")
        r["manual"] = False

    defaults = plan.get("defaults") or {}
    for r in rows:
        for k, v in defaults.items():
            if not r.get(k):
                r[k] = v

    by_id = {r["id"]: r for r in rows}
    explicit = set()
    orphans = []

    for item in plan.get("items") or []:
        if not isinstance(item, dict):
            continue
        if item.get("id"):
            target = by_id.get(item["id"])
            if not target:
                o = dict(item)
                o.setdefault("title", item["id"])
                o.setdefault("severity", "na")
                o.setdefault("priority", "P3")
                o["manual"] = True
                o["orphan"] = True
                orphans.append(o)
                continue
            for k, v in item.items():
                if k != "id":
                    target[k] = v
                    explicit.add((target["id"], k))
            target["manual"] = True

    for item in plan.get("items") or []:
        if not isinstance(item, dict) or item.get("id") or not item.get("match"):
            continue
        for r in rows:
            if not _matches(r, item["match"]):
                continue
            for k, v in item.items():
                if k in ("match",) or (r["id"], k) in explicit:
                    continue
                r[k] = v
            r["manual"] = True

    rows = [r for r in rows if not r.get("hide")]

    for extra in plan.get("extra") or []:
        if not isinstance(extra, dict) or not extra.get("id"):
            continue
        e = dict(extra)
        e.setdefault("severity", "info")
        e.setdefault("priority", "P3")
        e.setdefault("status", "abierto")
        e.setdefault("location", "—")
        e["manual"] = True
        rows.append(e)

    return rows + orphans, orphans


_SOURCE_LABEL = {"bandit": "Bandit", "npm": "npm audit", "pip": "pip-audit",
                 "zap": "ZAP", "sonar": "SonarQube", "owasp": "OWASP", "manual": "Manual"}


def remediation_rows_html(rows):
    body, attrs, snippets = [], [], []
    for r in rows:
        title = esc(r.get("title", ""), 90)
        if r.get("orphan"):
            title += ' <span class="pill s-na">sin hallazgo automático</span>'
        elif r.get("manual"):
            title += ' <span class="pill s-na">manual</span>'
        src = _SOURCE_LABEL.get(r.get("source", ""), "Manual")
        body.append([
            f'<div>{title}</div><div class="loc">{esc(src)}</div>',
            f'<span class="loc">{esc(r.get("location",""), 60)}</span>',
            pill(_SEV_LABEL.get(sev_key(r.get("severity")), "N/A"), r.get("severity")),
            esc(r.get("action", "") or r.get("detail", ""), 190) or "—",
            esc(r.get("owner", "")) or "—",
            f'<span class="num">{esc(r.get("eta",""))}</span>' or "—",
            pill(str(r.get("status", "abierto")).replace("-", " "), r.get("status")),
        ])
        attrs.append({"sev": sev_key(r.get("severity")),
                      "q": f'{_SOURCE_LABEL.get(r.get("source",""),"manual")} {r.get("title","")} '
                           f'{r.get("location","")} {r.get("rule","")}'.lower()})
        if r.get("before") or r.get("after"):
            pair = ""
            if r.get("before"):
                pair += code_block(r["before"], "Antes")
            if r.get("after"):
                pair += code_block(r["after"], "Después")
            snippets.append(
                f'<p class="prose"><strong>{esc(r.get("title",""), 90)}</strong></p>'
                f'<div class="code-pair">{pair}</div>'
            )
    out = table(
        ["Hallazgo", "Ubicación", "Severidad", "Acción", "Responsable", "ETA", "Estado"],
        body, "Sin hallazgos en esta prioridad.", attrs,
    )
    return out + "".join(snippets)


# ----------------------------------------------------------------------------
# Bloques por herramienta
# ----------------------------------------------------------------------------

def iter_zap_alerts(*docs):
    for doc in docs:
        if not doc:
            continue
        for site in doc.get("site", []):
            for alert in site.get("alerts", []):
                yield alert


def severity_totals(rows):
    totals = {"crit": 0, "high": 0, "med": 0, "low": 0, "info": 0}
    for r in rows:
        k = r.get("severity")
        if k in totals:
            totals[k] += 1
    return totals


def zap_ran():
    """¿Hay resultados de ZAP en disco? Es lo único que prueba que DAST corrió."""
    return bool(zap or zap_web or zap_api)


def has_target_url():
    return bool(zap_cfg.get("web_url") or zap_cfg.get("api_url")
                or zap_cfg.get("target_url"))


def http_surface():
    """¿El proyecto expone HTTP? Propiedad del código, independiente del scan."""
    if inventory.get("http_surface") is not None:
        return bool(inventory["http_surface"])
    kinds_set = set(inventory.get("kinds") or [])
    return bool(kinds_set & {"api", "web"}) or bool(inventory.get("openapi"))


def bandit_table():
    if not bandit:
        return callout("<p>No se ejecutó Bandit (sin archivos Python o script omitido).</p>",
                       "neutral")
    rows, attrs = [], []
    for r in bandit.get("results", [])[:200]:
        sev = r.get("issue_severity", "LOW")
        cwe = r.get("issue_cwe")
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else cwe
        rows.append([
            f'<span class="loc">{esc(r.get("test_id",""))}</span>',
            f'<span class="loc">{esc(r.get("filename",""))}:'
            f'{esc(r.get("line_number",""))}</span>',
            pill(_SEV_LABEL[sev_key(sev)], sev),
            f'<span class="num">{esc(cwe_id) if cwe_id else "—"}</span>',
            esc(r.get("issue_confidence", "")).title() or "—",
            esc(r.get("issue_text", ""), 200),
        ])
        attrs.append({"sev": sev_key(sev),
                      "q": f'bandit {r.get("test_id","")} {r.get("filename","")} '
                           f'{r.get("issue_text","")}'.lower()})
    return table(["Regla", "Ubicación", "Severidad", "CWE", "Confianza", "Descripción"],
                 rows, "Bandit no encontró hallazgos.", attrs)


def pip_audit_table():
    if not pip_audit:
        return callout("<p>No se ejecutó pip-audit.</p>", "neutral")
    deps = pip_audit.get("dependencies") if isinstance(pip_audit, dict) else pip_audit
    rows, attrs = [], []
    for dep in deps or []:
        if not isinstance(dep, dict):
            continue
        for v in dep.get("vulns", []) or []:
            fixes = v.get("fix_versions") or []
            rows.append([
                f'<span class="loc">{esc(dep.get("name",""))} '
                f'{esc(dep.get("version",""))}</span>',
                f'<span class="loc">{esc(v.get("id",""))}</span>',
                pill("Fix disponible", "med") if fixes else pill("Sin fix", "low"),
                esc(", ".join(fixes)) if fixes else "—",
                esc(v.get("description", ""), 180) or "—",
            ])
            attrs.append({"sev": "med" if fixes else "low",
                          "q": f'pip-audit {dep.get("name","")} {v.get("id","")}'.lower()})
    return table(["Paquete", "CVE / ID", "Estado", "Versión con fix", "Descripción"],
                 rows, "Sin vulnerabilidades en dependencias Python.", attrs)


def npm_audit_table():
    if not npm_audit:
        return callout(
            "<p>No se ejecutó el audit de Node (sin <code>package.json</code>).</p>", "neutral")

    entries, fmt, meta = sca_node_entries()

    warn = ""
    if not entries and meta:
        total = sum(v for v in meta.values() if isinstance(v, int))
        warn = callout(
            f"<p>El audit informa <strong>{total}</strong> vulnerabilidades en su resumen, "
            "pero no devolvió el detalle por paquete. Se muestran los totales; para el detalle, "
            "volvé a correr el audit del gestor que usa el proyecto.</p>",
            "warn", "Detalle incompleto")

    rows, attrs = [], []
    for e in sorted(entries, key=lambda x: _SEV_RANK.get(sev_key(x["severity"]), 9)):
        sev = e["severity"]
        # El advisory oficial: es la fuente de verdad sobre el CVE, no este reporte.
        name_cell = f'<span class="loc">{esc(e["package"])}</span>'
        if e["url"]:
            name_cell = (f'<a href="{esc(e["url"])}" target="_blank" rel="noopener" '
                         f'class="loc">{esc(e["package"])}</a>')
        cves = ", ".join(e["cves"][:3])
        detalle = esc(e["title"], 130) or "—"
        if cves:
            detalle += f'<br><span class="loc">{esc(cves)}</span>'
        fix_cell = (pill(f"→ {e['patched']}"[:22], "ok") if e["patched"] and e["fix"]
                    else (pill("Sí", "ok") if e["fix"] else pill("Sin fix", "low")))
        via = ""
        if e["paths"]:
            via = f'<br><span class="loc">vía {esc(e["paths"][0], 46)}</span>'
        rows.append([
            name_cell + via,
            pill(_SEV_LABEL[sev_key(sev)], sev),
            f'<span class="loc">{esc(e["range"], 34)}</span>' or "—",
            fix_cell,
            detalle,
        ])
        attrs.append({"sev": sev_key(sev),
                      "q": f'{fmt} audit {e["package"]} {e["title"]} {cves}'.lower()})

    tbl = table(["Paquete", "Severidad", "Versiones afectadas", "Fix", "Vulnerabilidad"],
                rows, "Sin vulnerabilidades en dependencias Node.", attrs)
    return warn + tbl


def zap_table_for(doc, empty_msg):
    rows, attrs = [], []
    for alert in iter_zap_alerts(doc):
        riskdesc = alert.get("riskdesc", "Informational")
        risk = riskdesc.split(" ")[0]
        inst = alert.get("instances") or []
        first = inst[0].get("uri", "") if inst else ""
        rows.append([
            esc(alert.get("name", "")),
            pill(_SEV_LABEL[sev_key(risk)], risk, title=riskdesc),
            f'<span class="num">{esc(alert.get("cweid")) if alert.get("cweid") else "—"}</span>',
            f'<span class="num">{esc(alert.get("count", len(inst) or 1))}</span>'
            + (f'<br><span class="loc">{esc(first, 48)}</span>' if first else ""),
            esc(alert.get("desc", ""), 200),
        ])
        attrs.append({"sev": sev_key(risk),
                      "q": f'zap dast {alert.get("name","")} {first}'.lower()})
    return table(["Alerta", "Riesgo", "CWE", "Instancias", "Descripción"],
                 rows, empty_msg, attrs)


def sonar_dashboard():
    if sonar and sonar.get("dashboard_url"):
        return sonar["dashboard_url"]
    if sonar_status.get("dashboard_url"):
        return sonar_status["dashboard_url"]
    if sonar_status.get("url"):
        key = sonar_status.get("project_key") or project.get("key") or ""
        return f"{sonar_status['url']}/dashboard?id={key}" if key else sonar_status["url"]
    return "http://localhost:9000"


def sonar_omit_reason():
    if sonar:
        return "Análisis exportado."
    if prereqs and prereqs.get("docker") != "ok":
        return "Omitido: Docker no está disponible o el daemon no está corriendo."
    if prereqs and prereqs.get("low_disk"):
        return "Pendiente u omitido por poco disco. Corré <code>--only sonar</code> cuando haya espacio."
    if prereqs and not prereqs.get("sonar_ready"):
        return "Omitido: imágenes o herramientas (jq/curl) no listas."
    return "No se ejecutó SonarQube."


def sonar_access_html():
    dash = sonar_dashboard()
    st = sonar_status.get("status") or ("up" if sonar else "unknown")
    login = sonar_status.get("login") or "admin"
    password = sonar_status.get("password") or f"Security_Scan_{datetime.now().year}!"
    pw_file = sonar_status.get("password_file") or "security-reports/.sonar-admin"
    has_export = bool(sonar_issues or sonar_hotspots)

    body = (
        f'<p>Dashboard: <a href="{esc(dash)}">{esc(dash)}</a><br>'
        f"Usuario <code>{esc(login)}</code> · contraseña <code>{esc(password)}</code> "
        f"(también en <code>{esc(pw_file)}</code>).</p>"
        "<p>Ese enlace es <strong>local y temporal</strong>: solo responde en esta máquina "
        "mientras el contenedor de Docker esté levantado. "
        + ("Para consultarlo después, o desde otra computadora, usá "
           "<code>sonarqube-issues.json</code> en los anexos."
           if has_export else
           "El detalle por issue <strong>no se exportó</strong>: si parás el contenedor se "
           "pierde. Volvé a correr el paso de SonarQube para generar "
           "<code>sonarqube-issues.json</code>.")
        + "</p>"
    )
    out = [callout(body, "warn" if not has_export else "info", "Acceso a SonarQube")]
    out.append(callout(
        "<p>Este reporte incluye la contraseña de SonarQube en texto plano. Antes de "
        "compartirlo fuera del equipo, revisá que eso sea aceptable.</p>", "warn",
        "Contiene una credencial",
    ))

    st_note = sonar_status.get("reason") or sonar_omit_reason()
    if not sonar:
        out.append(callout(f"<p>Estado: <code>{esc(st)}</code>. {st_note}</p>", "neutral"))
        return "".join(out)

    qg = str(sonar.get("quality_gate", "—"))
    dup = sonar.get("duplicated_lines_density")
    dup_s = f"{dup}%" if dup not in (None, "", "n/a") else "n/a"
    metrics = table(
        ["Métrica", "Valor"],
        [
            ["Quality gate", pill(qg, "ok" if qg.upper() == "OK" else
                                  ("high" if qg.upper() == "ERROR" else "na"))],
            ["Vulnerabilities", f'<span class="num">{esc(sonar.get("vulnerabilities", 0))}</span>'],
            ["Bugs", f'<span class="num">{esc(sonar.get("bugs", 0))}</span>'],
            ["Security hotspots", f'<span class="num">{esc(sonar.get("security_hotspots", 0))}</span>'],
            ["Code smells", f'<span class="num">{esc(sonar.get("code_smells", 0))}</span>'],
            ["Coverage", f'<span class="num">{esc(sonar.get("coverage", "n/a"))}</span>'],
            ["Duplicated lines", f'<span class="num">{esc(dup_s)}</span>'],
        ],
    )
    return "".join(out) + metrics


def sonar_issues_table():
    rows = [r for r in sonar_findings() if r["source"] == "sonar"]
    detailed = [r for r in rows if not r["id"].startswith(
        ("sonar:vulnerabilities", "sonar:bugs", "sonar:security_hotspots",
         "sonar:code_smells", "sonar:quality_gate"))]
    if not detailed:
        return ""
    body, attrs = [], []
    for r in detailed[:300]:
        body.append([
            f'<span class="loc">{esc(r["title"])}</span>',
            f'<span class="loc">{esc(r["location"], 60)}</span>',
            pill(_SEV_LABEL[r["severity"]], r["severity"]),
            esc(r["detail"], 180),
        ])
        attrs.append({"sev": r["severity"], "q": f'sonarqube {r["title"]} {r["location"]}'.lower()})
    return table(["Regla", "Ubicación", "Severidad", "Mensaje"], body,
                 "Sin issues.", attrs)


def owasp_table(rows, na_msg):
    if not rows:
        return callout(f"<p>{na_msg}</p>", "neutral")
    body, attrs = [], []
    for row in rows:
        st = row.get("status", "clear")
        findings = row.get("findings") or []
        ev = "; ".join(
            f'{f.get("source","")}: {esc(f.get("name",""), 70)}' for f in findings[:4]
        ) or "—"
        rev = row.get("review") or {}
        if rev.get("evidence"):
            ev += f' · <em>revisión:</em> {esc(rev["evidence"], 160)}'
        cwes = sorted({str(f.get("cwe")) for f in findings if f.get("cwe")})
        label = {"hit": "Hallazgo", "clear": "Sin evidencia", "n/a": "N/A"}.get(st, st)
        body.append([
            f'<strong>{esc(row.get("id",""))}</strong><br>'
            f'<span class="loc">{esc(row.get("name",""))}</span>',
            pill(label, st),
            f'<span class="num">{esc(", ".join(cwes[:4])) if cwes else "—"}</span>',
            ev,
        ])
        attrs.append({"sev": sev_key(st),
                      "q": f'owasp {row.get("id","")} {row.get("name","")}'.lower()})
    return table(["Ítem", "Estado", "CWE", "Evidencia"], body, na_msg, attrs)


def zap_targets_html():
    parts = []
    for label, key in (("web", "web_url"), ("api", "api_url")):
        if zap_cfg.get(key):
            parts.append(f'{label}: <code>{esc(zap_cfg[key])}</code>')
    if not parts and zap_cfg.get("target_url"):
        parts.append(f'target: <code>{esc(zap_cfg["target_url"])}</code>')
    if not parts:
        return callout(
            "<p>No se ejecutó ZAP: no se dio ninguna URL HTTP. "
            "El análisis estático sigue siendo válido — DAST es complementario, no un "
            "requisito.</p>", "neutral", "DAST omitido")
    return callout(
        "<p>Objetivos: " + " · ".join(parts) + "</p>"
        "<p>ZAP corre dentro de Docker, así que <code>host.docker.internal</code> apunta a "
        "esta misma máquina. La aplicación bajo prueba no necesita estar en Docker.</p>",
        "info", "Objetivos analizados")


def inventory_html():
    kinds = ", ".join(inventory.get("kinds") or ["desconocido"])
    stacks = ", ".join(inventory.get("stacks") or ["—"])
    dirs = ", ".join(inventory.get("top_dirs") or []) or "—"
    specs = ", ".join(inventory.get("openapi") or []) or "ninguno"
    # Tres estados distintos, no dos: que el proyecto exponga HTTP no significa
    # que se haya corrido DAST, y decir lo contrario sería afirmar una cobertura
    # que no existe.
    if zap_ran():
        dast = "DAST ejecutado: ZAP corrió contra las URLs indicadas."
    elif http_surface():
        dast = ("El proyecto expone HTTP, pero <strong>no se ejecutó DAST</strong>: no se "
                "indicó una URL alcanzable. El análisis estático cubre igual toda la "
                "carpeta; para sumar DAST, volvé a correr el scan con "
                "<code>--web-url</code> o <code>--api-url</code>.")
    else:
        dast = ("Sin superficie HTTP detectada: DAST no aplica. El análisis estático "
                "cubre toda la carpeta.")
    return callout(
        f"<p>Tipos detectados: <code>{esc(kinds)}</code> · stacks: <code>{esc(stacks)}</code></p>"
        f"<p>Carpetas raíz: <code>{esc(dirs)}</code> · OpenAPI: <code>{esc(specs)}</code></p>"
        f"<p>{dast}</p>", "neutral", "Qué se analizó")


def prereqs_html():
    if not prereqs:
        return ""
    disk = prereqs.get("disk_free_gb") or ""
    bits = [f'Docker <code>{esc(prereqs.get("docker","desconocido"))}</code>']
    if disk:
        bits.append(f"disco libre <code>{esc(disk)} GB</code>")
    notes = prereqs.get("notes") or []
    extra = ""
    if prereqs.get("low_disk"):
        extra = ("<p>Poco espacio libre: conviene correr un scanner por vez "
                 "(<code>--only sast|sonar|zap</code>) para que no fallen todos juntos.</p>")
    lst = ("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in notes) + "</ul>") if notes else ""
    return callout(f"<p>{' · '.join(bits)}</p>{extra}{lst}", "neutral", "Preflight")


# ----------------------------------------------------------------------------
# Anexos: los reportes crudos de cada herramienta, enlazados en relativo.
# ----------------------------------------------------------------------------

_ANNEXES = [
    ("zap-dast-report.html", "OWASP ZAP", "Reporte nativo: alertas, instancias, evidencia y solución"),
    ("zap-dast-web.html", "OWASP ZAP", "Reporte nativo del objetivo web"),
    ("zap-dast-api.html", "OWASP ZAP", "Reporte nativo del objetivo API"),
    ("zap-dast-report.json", "OWASP ZAP", "Mismo contenido, procesable"),
    ("zap-dast-web.json", "OWASP ZAP", "Alertas del objetivo web en JSON"),
    ("zap-dast-api.json", "OWASP ZAP", "Alertas del objetivo API en JSON"),
    ("sonarqube-issues.json", "SonarQube", "Todos los issues: regla, archivo, línea, esfuerzo"),
    ("sonarqube-hotspots.json", "SonarQube", "Security hotspots con su contexto"),
    ("sonarqube-summary.json", "SonarQube", "Contadores agregados y quality gate"),
    ("sonar-scanner.log", "SonarQube", "Log del scanner, para diagnosticar fallas"),
    ("bandit-report.json", "Bandit", "Salida cruda, incluye el fragmento de código y more_info"),
    ("npm-audit-report.json", "npm audit", "Árbol de dependencias Node vulnerables"),
    ("pip-audit-report.json", "pip-audit", "Dependencias Python vulnerables"),
    ("owasp-summary.json", "Skill", "Mapeo de hallazgos contra OWASP Top 10 y API Top 10"),
    ("owasp-review.json", "Skill", "Revisión manual de los ítems que las herramientas no cubren"),
    ("remediation-plan.json", "Skill", "Acciones, responsables y fechas del plan"),
    ("inventory.json", "Skill", "Inventario del repo: tipos, stacks, specs"),
    ("prereqs.json", "Skill", "Estado de Docker, imágenes y espacio en disco"),
]


def annexes_html():
    rows = []
    for fname, tool, desc in _ANNEXES:
        p = OUT_DIR / fname
        if not p.exists():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        kb = size / 1024
        size_s = f"{size} B" if size < 1024 else (
            f"{kb:.1f} KB" if kb < 1024 else f"{kb/1024:.1f} MB")
        rows.append([
            f'<a href="{esc(fname)}">{icon("link")} {esc(fname)}</a>',
            esc(tool),
            esc(desc),
            f'<span class="num">{esc(size_s)}</span>',
        ])
    intro = callout(
        "<p>Estos son los reportes originales de cada herramienta, sin procesar. Sirven para "
        "consultar un detalle puntual que este resumen no muestra. Los enlaces son relativos: "
        "comprimí la carpeta <code>security-reports/</code> completa y el reporte sigue "
        "navegable para quien lo reciba.</p>", "neutral", "Fuentes originales")
    warn = callout(
        "<p>Antes de compartir la carpeta, revisá su contenido. El reporte de ZAP incluye "
        "peticiones y respuestas completas, y <code>.sonar-admin</code> guarda la contraseña "
        "de SonarQube. Por eso <code>security-reports/</code> está en <code>.gitignore</code>: "
        "no se commitea.</p>", "warn", "Pueden contener datos sensibles")
    if not rows:
        return intro + callout("<p>No quedó ningún artefacto en esta corrida.</p>", "neutral")
    return intro + table(
        ["Archivo", "Herramienta", "Contenido", "Tamaño"], rows, "Sin artefactos."
    ) + warn


# ----------------------------------------------------------------------------
# Chrome del documento
# ----------------------------------------------------------------------------

FINDINGS = all_findings()
TOTALS = severity_totals(FINDINGS)
P1_COUNT = sum(1 for f in FINDINGS if f["priority"] == "P1")
P2_COUNT = sum(1 for f in FINDINGS if f["priority"] == "P2")


def report_meta(key, fallback=""):
    return (REPORT.get(key) or "").strip() if isinstance(REPORT.get(key), str) else fallback


REPORT_TYPE = report_meta("report_type") or "Reporte de Seguridad de Aplicaciones"
CLASSIFICATION = report_meta("classification") or "Uso Interno · Confidencial"
DOC_VERSION = report_meta("document_version") or "1.0"
ANALYSIS_DATE = report_meta("analysis_date") or date_str


def status_label():
    custom = report_meta("status_label")
    if custom:
        return custom
    if P1_COUNT:
        return f"{P1_COUNT} hallazgo(s) de prioridad P1"
    if P2_COUNT:
        return f"{P2_COUNT} hallazgo(s) de prioridad P2"
    return "Sin hallazgos de prioridad alta"


def endpoint_value():
    ep = report_meta("endpoint")
    if ep:
        return esc(ep)
    urls = [zap_cfg[k] for k in ("web_url", "api_url", "target_url") if zap_cfg.get(k)]
    if urls:
        return " · ".join(f'<code>{esc(u)}</code>' for u in dict.fromkeys(urls))
    # No decir "no aplica" cuando el proyecto sí expone HTTP: el cuerpo del
    # reporte afirma lo contrario y la contradicción resta credibilidad.
    if http_surface():
        return "No indicado (el proyecto expone HTTP, pero no se dio una URL)"
    return "No aplica (sin superficie HTTP)"


def code_scope_value():
    cs = report_meta("code_scope")
    if cs:
        return esc(cs)
    stacks = inventory.get("stacks") or []
    dirs = inventory.get("top_dirs") or []
    if not stacks and not dirs:
        return ""
    bits = []
    if stacks:
        bits.append(", ".join(esc(s) for s in stacks))
    if dirs:
        bits.append(f"{len(dirs)} carpeta(s) raíz")
    return " · ".join(bits)


def tools_used():
    versions = REPORT.get("tool_versions") or {}
    images = (prereqs or {}).get("images") or {}
    out = []
    if sonar or sonar_issues:
        out.append(("SonarQube", versions.get("SonarQube", "")
                    or ("Community" if "sonarqube:community" in images else "")))
    if bandit:
        out.append(("Bandit", versions.get("Bandit", "")))
    if zap or zap_web or zap_api:
        out.append(("OWASP ZAP", versions.get("OWASP ZAP", "")))
    if npm_audit:
        out.append(("npm audit", versions.get("npm audit", "")))
    if pip_audit:
        out.append(("pip-audit", versions.get("pip-audit", "")))
    return out


def coverage_html():
    """Qué corrió y cuánto encontró. Es dato accionable, no una etiqueta sobre el título."""
    def n_of(*sources):
        return sum(1 for f in FINDINGS if f["source"] in sources)

    items = [
        ("SAST", bool(bandit or sonar or sonar_issues), n_of("bandit", "sonar")),
        ("SCA", bool(npm_audit or pip_audit), n_of("npm", "pip")),
        ("DAST", bool(zap or zap_web or zap_api), n_of("zap")),
        ("OWASP", bool(owasp.get("web") or owasp.get("api")), n_of("owasp")),
    ]
    lis = []
    for label, ran, count in items:
        if ran:
            txt = f"{count} hallazgo{'s' if count != 1 else ''}" if count else "sin hallazgos"
            lis.append(f'<li class="cov"><b>{label}</b><span>{txt}</span></li>')
        else:
            lis.append(f'<li class="cov is-off"><b>{label}</b><span>no ejecutado</span></li>')
    return f'<ul class="coverage">{"".join(lis)}</ul>'


def masthead_html():
    return (
        '<header class="masthead"><div class="wrap">'
        f'<span class="m-type">{esc(REPORT_TYPE)}</span>'
        f'<span class="m-class">{esc(CLASSIFICATION)} · {esc(ANALYSIS_DATE)}</span>'
        "</div></header>"
    )


def head_html():
    tools = tools_used()
    tools_line = " · ".join(
        f"{esc(n)}{' ' + esc(v) if v else ''}" for n, v in tools
    ) or "sin herramientas ejecutadas"
    meta = kv_grid([
        ("Preparado por", esc(report_meta("prepared_by"))),
        ("Fecha del análisis", esc(ANALYSIS_DATE)),
        ("Alcance del código", code_scope_value()),
        ("Infraestructura", esc(report_meta("infrastructure"))),
        ("Endpoint analizado", endpoint_value()),
        ("Versión del documento", esc(DOC_VERSION)),
        ("Herramientas", tools_line),
        ("Organización", esc(COMPANY_NAME)),
    ])
    return (
        '<div class="head"><div class="wrap">'
        f"<h1>Análisis de Seguridad — {esc(PROJECT_NAME)}</h1>"
        f'<div class="h-status"><span class="doc-pill">{icon("check")}'
        f"Versión {esc(DOC_VERSION)} — {esc(status_label())}</span></div>"
        f"{coverage_html()}{meta}"
        "</div></div>"
    )


def toolbar_html():
    counts = [("crit", "Crítico"), ("high", "Alto"), ("med", "Medio"), ("low", "Bajo")]
    btns = "".join(
        f'<li><button type="button" class="f-btn" data-sev="{k}" aria-pressed="false">'
        f'{label} <b>{TOTALS.get(k, 0)}</b></button></li>'
        for k, label in counts
    )
    return (
        '<div class="toolbar no-print"><div class="wrap">'
        f'<ul class="filters">{btns}</ul>'
        f'<div class="t-search">{icon("search")}'
        '<input type="search" id="q" placeholder="Buscar archivo, regla o CWE"'
        ' aria-label="Buscar en el reporte"></div>'
        f'<button type="button" class="btn-print" id="print">{icon("print")}'
        "Imprimir / PDF</button>"
        "</div></div>"
    )


def sidebar_html(tabs):
    return (
        '<aside class="side no-print">'
        f'<div class="side-brand">{icon("shield")}Análisis de Seguridad</div>'
        f'<p class="side-proj">{esc(PROJECT_NAME)}</p>'
        f"{render_nav(tabs)}"
        f'<div class="side-foot">{esc(CLASSIFICATION)}<br>{esc(ANALYSIS_DATE)} · '
        f"v{esc(DOC_VERSION)}</div>"
        "</aside>"
    )


def footer_html():
    tools = " · ".join(f"{esc(n)}{' ' + esc(v) if v else ''}" for n, v in tools_used())
    org = f"<span><b>{esc(COMPANY_NAME)}</b></span>" if COMPANY_NAME else ""
    return (
        '<footer class="foot"><div class="wrap">'
        f"{org}<span><b>{esc(PROJECT_NAME)}</b> — {esc(REPORT_TYPE)}</span>"
        f"<span>{esc(CLASSIFICATION)}</span><span>{esc(ANALYSIS_DATE)}</span>"
        f"<span>v{esc(DOC_VERSION)}</span>"
        + (f"<span>{tools}</span>" if tools else "")
        + '<span>Generado por <code>/lc2tech:skill-security-scan</code></span>'
        "</div></footer>"
    )


def summary_table():
    rows = []
    if sonar or sonar_issues:
        qg = str((sonar or {}).get("quality_gate", "—"))
        qg_pill = pill(f"QG {qg}", "ok" if qg.upper() == "OK" else
                       ("high" if qg.upper() == "ERROR" else "na"))
        sonar_rows = [r for r in sonar_findings()
                      if not r["id"].startswith(("sonar:vulnerabilities", "sonar:bugs",
                                                 "sonar:security_hotspots",
                                                 "sonar:code_smells", "sonar:quality_gate"))]
        if sonar_rows:
            s = severity_totals(sonar_rows)
            cells = [f'<span class="num">{s["crit"] + s["high"]}</span>',
                     f'<span class="num">{s["med"]}</span>',
                     f'<span class="num">{s["low"]}</span>']
            estado = qg_pill
        else:
            # Sin export por issue no hay severidades reales: los contadores de Sonar
            # (vulns / bugs / smells) no son niveles de severidad y alinearlos bajo
            # esas columnas sería inventar un dato. Se muestran como lo que son.
            m = sonar or {}
            cells = ["—", "—", "—"]
            estado = (qg_pill + '<br><span class="loc">'
                      f'{esc(m.get("vulnerabilities", 0))} vulns · '
                      f'{esc(m.get("bugs", 0))} bugs · '
                      f'{esc(m.get("code_smells", 0))} smells</span>')
        rows.append(["SAST — SonarQube", "SonarQube Community", *cells, estado])
    else:
        rows.append(["SAST — SonarQube", "SonarQube Community", "—", "—", "—",
                     pill("No ejecutado", "na")])

    b = severity_totals(bandit_findings())
    rows.append(["SAST — Python", "Bandit",
                 f'<span class="num">{b["crit"] + b["high"]}</span>',
                 f'<span class="num">{b["med"]}</span>',
                 f'<span class="num">{b["low"]}</span>',
                 pill("Ejecutado", "ok") if bandit else pill("No ejecutado", "na")])

    n = severity_totals(npm_findings())
    rows.append(["SCA — Node.js", "npm audit",
                 f'<span class="num">{n["crit"] + n["high"]}</span>',
                 f'<span class="num">{n["med"]}</span>',
                 f'<span class="num">{n["low"]}</span>',
                 pill("Ejecutado", "ok") if npm_audit else pill("No ejecutado", "na")])

    p = severity_totals(pip_findings())
    rows.append(["SCA — Python", "pip-audit",
                 f'<span class="num">{p["crit"] + p["high"]}</span>',
                 f'<span class="num">{p["med"]}</span>',
                 f'<span class="num">{p["low"]}</span>',
                 pill("Ejecutado", "ok") if pip_audit else pill("No ejecutado", "na")])

    z = severity_totals(zap_findings())
    rows.append(["DAST", "OWASP ZAP",
                 f'<span class="num">{z["crit"] + z["high"]}</span>',
                 f'<span class="num">{z["med"]}</span>',
                 f'<span class="num">{z["low"]}</span>',
                 pill("Ejecutado", "ok") if (zap or zap_web or zap_api)
                 else pill("Omitido", "na")])

    head = table(["Categoría", "Herramienta", "Alto / Crítico", "Medio", "Bajo", "Estado"], rows)
    verdict_kind = "warn" if P1_COUNT else ("info" if P2_COUNT else "ok")
    verdict = callout(
        f"<p>Se registraron <strong>{len(FINDINGS)}</strong> hallazgos: "
        f"{TOTALS['crit']} críticos, {TOTALS['high']} altos, {TOTALS['med']} medios y "
        f"{TOTALS['low']} bajos. "
        + (f"<strong>{P1_COUNT}</strong> requieren atención inmediata (P1); el plan de "
           "remediación los lista primero." if P1_COUNT else
           "Ninguno alcanza prioridad P1.")
        + "</p>", verdict_kind, "Resultado")
    return verdict + head


# ----------------------------------------------------------------------------
# Ensamblado
# ----------------------------------------------------------------------------

def render_nav(tabs):
    """Índice: en el sidebar y en el desplegable móvil. Los enlaces cambian de
    pestaña vía JS; sin JS son anclas al panel, que igual está visible."""
    links = "".join(
        f'<a href="#tp-{t.id}" data-tab="{t.id}"><span class="n">{i}</span>'
        f"<span>{esc(t.label)}</span></a>"
        for i, t in enumerate(tabs, 1))
    return f"<nav>{links}</nav>"


class Tab:
    """Una pestaña en pantalla; una sección con salto de página al imprimir."""

    def __init__(self, tid, label, body):
        self.id = tid
        self.label = label
        self.body = body or ""


def render_tabs(tabs):
    btns = "".join(
        f'<button type="button" role="tab" class="tab-btn" id="tb-{t.id}" '
        f'aria-controls="tp-{t.id}" aria-selected="{"true" if i == 0 else "false"}" '
        f'tabindex="{"0" if i == 0 else "-1"}">{esc(t.label)}</button>'
        for i, t in enumerate(tabs))
    # Sin `hidden` en el marcado: si el JS no corre, el lector debe ver el
    # documento completo en secuencia, no una sola pestaña.
    panels = "".join(
        f'<section role="tabpanel" class="tab-panel{" is-active" if i == 0 else ""}" '
        f'id="tp-{t.id}" aria-labelledby="tb-{t.id}">'
        f'<h2 class="panel-h">{esc(t.label)}</h2>{t.body}</section>'
        for i, t in enumerate(tabs))
    return (f'<div class="tabbar no-print" role="tablist" '
            f'aria-label="Tipos de análisis">{btns}</div>'
            f'<div class="tab-panels">{panels}</div>')


def sonar_typed_table(items, empty, hotspot=False):
    """Tabla de issues de Sonar con enlace a la regla oficial."""
    rows, attrs = [], []
    for it in items[:300]:
        comp = (it.get("component") or "").split(":")[-1]
        line = it.get("line")
        rule = it.get("rule", "") or it.get("securityCategory", "")
        sev = it.get("severity") or it.get("vulnerabilityProbability") or "INFO"
        url = rule_url(rule, "sonar")
        rule_cell = (f'<a href="{esc(url)}" target="_blank" rel="noopener" class="loc">'
                     f'{esc(rule)}</a>' if url else f'<span class="loc">{esc(rule)}</span>')
        rows.append([
            rule_cell,
            f'<span class="loc">{esc(comp, 58)}{":" + str(line) if line else ""}</span>',
            pill(_SEV_LABEL[sev_key(sev)], sev),
            esc(it.get("message", ""), 160),
        ])
        attrs.append({"sev": sev_key(sev),
                      "q": f'sonarqube {rule} {comp} {it.get("message","")}'.lower()})
    extra = ""
    if len(items) > 300:
        extra = (f'<p class="more-note">Se muestran 300 de {len(items)}. El listado completo '
                 "está en <code>sonarqube-issues.json</code>, en Anexos.</p>")
    return table(["Regla", "Ubicación", "Severidad Sonar", "Mensaje"], rows,
                 empty, attrs) + extra


def remediation_full_html():
    """El plan completo, en su propia pestaña."""
    out = []
    if REMEDIATION_BROKEN:
        out.append(callout(
            "<p><code>remediation-plan.json</code> existe pero no es JSON válido, así que se "
            "ignoró: abajo está solo la clasificación automática.</p>",
            "warn", "El plan manual no se pudo leer"))
    out.append(callout(
        "<p>Las prioridades se derivan del origen y la severidad de cada hallazgo. "
        "<strong>P1</strong> requiere acción inmediata por seguridad; <strong>P2</strong> se "
        "planifica; <strong>P3</strong> es backlog y deuda de calidad. Un bug de correctitud "
        "no escala a P1 aunque la herramienta lo marque alto: P1 está reservado a seguridad."
        + ("" if isinstance(remediation, dict) else
           " Para sumar acción, responsable y fecha, escribí "
           "<code>remediation-plan.json</code>.")
        + "</p>", "neutral", "Cómo leer este plan"))
    notes = (remediation or {}).get("notes") if isinstance(remediation, dict) else None
    if notes:
        out.append(callout("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in notes) + "</ul>",
                           "neutral", "Notas de la revisión"))
    for prio, label in (("P1", "P1 — Crítico · acción inmediata"),
                        ("P2", "P2 — Planificado"),
                        ("P3", "P3 — Backlog y calidad")):
        bucket = [r for r in MERGED_ROWS if r.get("priority") == prio]
        out.append(f'<h3><span class="s-num">{prio[1]}</span> {esc(label)} · {len(bucket)}</h3>')
        out.append(remediation_rows_html(bucket) if bucket
                   else callout("<p>Sin hallazgos en esta prioridad.</p>", "ok"))
    if MERGED_ORPHANS:
        out.append(callout(
            f"<p>{len(MERGED_ORPHANS)} entrada(s) del plan apuntan a un id que ya no existe "
            "en los hallazgos, normalmente tras un re-scan que cambió rutas o líneas. Se "
            "muestran igual para no perderlas.</p>", "warn",
            "Entradas manuales sin hallazgo correspondiente"))
    return "".join(out)


def methodology_html():
    return callout(
        "<p>El análisis estático (SAST) y de dependencias (SCA) cubren toda la carpeta del "
        "proyecto. El análisis dinámico (DAST) solo corre contra una URL alcanzable; su "
        "ausencia no invalida el resto, pero deja sin probar el comportamiento en ejecución.</p>"
        "<p>En el mapeo OWASP, <code>Sin evidencia</code> significa que ninguna herramienta "
        "reportó algo asociable a ese ítem — <strong>no es una aprobación</strong>. Los "
        "controles que requieren criterio humano se revisan a mano y quedan registrados en "
        "<code>owasp-review.json</code> con su evidencia.</p>"
        "<p>Las severidades son las que reporta cada herramienta. La prioridad P1/P2/P3, en "
        "cambio, es del reporte: pondera el origen del hallazgo, porque la escala de una "
        "herramienta de calidad no es comparable con la de un CVE.</p>",
        "neutral", "Metodología")


# --- Filas del plan, calculadas una sola vez y reutilizadas por las pestañas ---
MERGED_ROWS, MERGED_ORPHANS = merge_remediation(all_findings(), remediation)


def verdict_html():
    """Un dictamen con postura. Un informe que no concluye nada obliga al lector
    a hacer el trabajo del analista."""
    v = (assessment.get("verdict") or {}) if isinstance(assessment, dict) else {}
    p1 = [r for r in MERGED_ROWS if r.get("priority") == "P1"
          and sev_key(r.get("status")) != "ok"]
    secrets = [r for r in p1 if "secret" in (r.get("rule", "") or "").lower()
               or "S6334" in (r.get("rule", "") or "") or "S6708" in (r.get("rule", "") or "")]

    status = v.get("status") or (
        "no-apto" if secrets or len(p1) >= 10 else
        ("reservas" if p1 else "apto"))
    label = {"no-apto": "No apto para producción",
             "reservas": "Apto con reservas",
             "apto": "Sin bloqueantes detectados"}.get(status, status)
    kind = {"no-apto": "warn", "reservas": "info", "apto": "ok"}.get(status, "neutral")

    if v.get("summary"):
        summary = esc(v["summary"])
    elif secrets:
        summary = (f"Se encontraron credenciales en archivos versionados y {len(p1)} "
                   "hallazgos de prioridad P1. Las credenciales expuestas se consideran "
                   "comprometidas hasta que se roten.")
    elif p1:
        summary = (f"{len(p1)} hallazgos requieren atención inmediata antes de considerar "
                   "este código listo para producción.")
    else:
        summary = ("No se detectaron hallazgos de prioridad P1 con las herramientas "
                   "aplicadas. Revisá el alcance para saber qué quedó sin probar.")

    reasons = v.get("reasons") or []
    if not reasons:
        by_src = {}
        for r in p1:
            # Las entradas de `extra[]` no traen source: son revisión manual.
            k = r.get("source") or "manual"
            by_src[k] = by_src.get(k, 0) + 1
        reasons = [f"{n} hallazgo(s) P1 en {_SOURCE_LABEL.get(k, 'revisión manual')}"
                   for k, n in sorted(by_src.items(), key=lambda x: -x[1])[:3]]
    lst = ("<ul>" + "".join(f"<li>{esc(r)}</li>" for r in reasons) + "</ul>") if reasons else ""
    tochange = v.get("to_change") or "Cerrar los P1 y volver a escanear."
    return callout(
        f"<p><strong>{esc(label)}.</strong> {summary}</p>{lst}"
        f"<p><strong>Para cambiar este dictamen:</strong> {esc(tochange)}</p>",
        kind, "Veredicto")


def scope_html():
    """Qué se probó y qué no. Declarar los límites es lo que distingue un
    informe con rigor de uno que se presenta como exhaustivo sin serlo."""
    sc = (assessment.get("scope") or {}) if isinstance(assessment, dict) else {}
    tested = list(sc.get("tested") or [])
    not_tested = list(sc.get("not_tested") or [])

    if not tested:
        if sonar or sonar_issues:
            tested.append("Análisis estático de todo el repositorio con SonarQube")
        if bandit:
            tested.append("Análisis estático de Python con Bandit")
        if npm_audit or pip_audit:
            tested.append("Auditoría del árbol de dependencias contra bases de CVE")
        if zap_ran():
            urls = [u for u in (zap_cfg.get("web_url"), zap_cfg.get("api_url"),
                                zap_cfg.get("target_url")) if u]
            tested.append("Escaneo dinámico sin autenticar sobre " +
                          (", ".join(dict.fromkeys(urls)) or "el objetivo indicado"))
        if owasp.get("api") or owasp.get("web"):
            tested.append("Revisión manual de autorización contra OWASP API Top 10")

    if not not_tested:
        cov = str((sonar or {}).get("coverage", "")).replace("%", "")
        try:
            if float(cov or 0) == 0:
                not_tested.append("Pruebas unitarias: el proyecto no tiene cobertura (0%), "
                                  "así que no hay red de seguridad ante regresiones")
        except ValueError:
            pass
        if zap_ran():
            not_tested.append("Superficie autenticada: el escaneo dinámico corrió sin "
                              "credenciales, por lo que los endpoints tras login no se probaron")
            not_tested.append("Lógica de negocio: ninguna herramienta automática valida reglas "
                              "propias del dominio")
        else:
            not_tested.append("Análisis dinámico: no se indicó una URL alcanzable")
        not_tested.append("Infraestructura fuera del repositorio: permisos IAM, reglas de red y "
                          "configuración del proveedor no se revisaron")
        not_tested.append("Pruebas de carga y denegación de servicio")

    def col(title, items, kind):
        body = "<ul>" + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>"
        return callout(body, kind, title)

    return ('<div class="two-col">'
            + col("Qué se probó", tested or ["Sin datos"], "ok")
            + col("Qué NO se probó", not_tested or ["Sin datos"], "warn")
            + "</div>")


def smells_html():
    """Deuda técnica agrupada por regla: 5888 filas sueltas no se leen, y no son
    hallazgos de seguridad."""
    smells = sonar_issue_list().get("CODE_SMELL") or []
    if not smells:
        return ""
    groups = {}
    for it in smells:
        r = it.get("rule", "?")
        g = groups.setdefault(r, {"n": 0, "msg": it.get("message", ""), "sev": it.get("severity")})
        g["n"] += 1
    top = sorted(groups.items(), key=lambda kv: -kv[1]["n"])[:15]
    rows = []
    for rule, g in top:
        url = rule_url(rule, "sonar")
        cell = (f'<a href="{esc(url)}" target="_blank" rel="noopener" class="loc">{esc(rule)}</a>'
                if url else f'<span class="loc">{esc(rule)}</span>')
        rows.append([cell, f'<span class="num">{g["n"]}</span>',
                     pill(_SEV_LABEL[sev_key(g["sev"])], g["sev"]),
                     esc(g["msg"], 120)])
    resto = len(smells) - sum(g["n"] for _, g in top)
    extra = (f'<p class="more-note">Y {resto} ocurrencias más repartidas en '
             f'{len(groups)-len(top)} reglas.</p>') if resto > 0 else ""
    return (callout(
        f"<p>SonarQube reportó <strong>{len(smells)}</strong> code smells en "
        f"<strong>{len(groups)}</strong> reglas distintas. <strong>No son "
        "vulnerabilidades</strong>: son mantenibilidad. Se listan agrupados porque el detalle "
        "fila por fila no aporta y sí ahoga los hallazgos de seguridad.</p>",
        "neutral", "Deuda técnica, no seguridad")
        + table(["Regla", "Ocurrencias", "Severidad Sonar", "Mensaje tipo"], rows,
                "Sin code smells.")
        + extra)


# ============================================================================
# Capa de análisis: qué es cada uno, con qué se hizo y qué conviene hacer.
# ============================================================================

assessment = load_json("assessment.json") or {}

ANALYSIS = {
    "sast": {
        "label": "SAST",
        "title": "Análisis estático del código",
        "what": (
            "Lee el código fuente sin ejecutarlo, buscando patrones que suelen terminar en "
            "vulnerabilidad: credenciales escritas en el código, consultas armadas por "
            "concatenación, criptografía débil, validaciones ausentes. Encuentra el problema "
            "en la línea exacta, antes de que llegue a correr."
        ),
        "limit": (
            "No sabe si una ruta es alcanzable en la práctica, así que produce falsos "
            "positivos. Cada hallazgo necesita confirmación humana."
        ),
        "tools": [
            ("SonarQube", "https://docs.sonarsource.com/sonarqube/latest/"),
            ("Catálogo de reglas", "https://rules.sonarsource.com/"),
            ("Bandit", "https://bandit.readthedocs.io/en/latest/"),
        ],
        "sources": ("sonar", "bandit"),
        "files": ("sonarqube-issues.json", "sonarqube-hotspots.json",
                  "sonarqube-summary.json", "bandit-report.json"),
    },
    "sca": {
        "label": "SCA",
        "title": "Composición de software (dependencias)",
        "what": (
            "No mira el código que escribiste, sino las librerías que instalaste. Compara el "
            "árbol de dependencias contra bases públicas de vulnerabilidades conocidas (CVE). "
            "La mayoría del código que corre en producción es de terceros, y es la superficie "
            "que más rápido envejece."
        ),
        "limit": (
            "Detecta que una versión vulnerable está instalada, no si tu código llega a "
            "ejecutar la parte afectada. Una dependencia de desarrollo pesa menos que una que "
            "corre en producción."
        ),
        "tools": [
            ("pnpm audit", "https://pnpm.io/cli/audit"),
            ("npm audit", "https://docs.npmjs.com/cli/commands/npm-audit"),
            ("GitHub Advisory Database", "https://github.com/advisories"),
            ("pip-audit", "https://pypi.org/project/pip-audit/"),
        ],
        "sources": ("npm", "pip"),
        "files": ("npm-audit-report.json", "pip-audit-report.json"),
    },
    "dast": {
        "label": "DAST",
        "title": "Análisis dinámico sobre la aplicación viva",
        "what": (
            "Ataca la aplicación corriendo, como lo haría alguien desde afuera: manda "
            "peticiones, prueba cabeceras, inyecta cargas y observa las respuestas. No ve el "
            "código; ve el comportamiento real, incluyendo lo que aporta la infraestructura "
            "(proxy, CDN, gateway)."
        ),
        "limit": (
            "Solo cubre lo que alcanza a recorrer. Sin credenciales válidas ni especificación "
            "completa, la superficie autenticada queda sin probar."
        ),
        "tools": [
            ("OWASP ZAP", "https://www.zaproxy.org/docs/"),
            ("Baseline vs Active scan", "https://www.zaproxy.org/docs/docker/about/"),
        ],
        "sources": ("zap",),
        "files": ("zap-dast-api.html", "zap-dast-web.html", "zap-dast-report.html"),
    },
    "owasp": {
        "label": "OWASP",
        "title": "Cobertura contra OWASP Top 10 y API Top 10",
        "what": (
            "No es una herramienta más: es el marco con el que se ordenan los hallazgos de "
            "todas las anteriores. Cada ítem del Top 10 se marca según lo que reportaron las "
            "herramientas y según revisión manual, porque los controles de autorización no se "
            "detectan automáticamente — hay que leer el código y entender el modelo de negocio."
        ),
        "limit": (
            "«Sin evidencia» significa que ninguna herramienta reportó algo asociable, no que "
            "el control esté correctamente implementado."
        ),
        "tools": [
            ("OWASP Top 10 (2021)", "https://owasp.org/Top10/"),
            ("OWASP API Security Top 10 (2023)",
             "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"),
            ("CWE", "https://cwe.mitre.org/"),
        ],
        "sources": ("owasp",),
        "files": ("owasp-summary.json", "owasp-review.json"),
    },
}


def rule_url(rule, source):
    """Enlace a la regla oficial. Poder verificar el criterio es lo que separa
    un informe consultable de una lista de mensajes."""
    if not rule:
        return ""
    if source == "sonar" and ":" in rule:
        lang, rid = rule.split(":", 1)
        if rid.upper().startswith("S") and rid[1:].isdigit():
            return f"https://rules.sonarsource.com/{lang}/RSPEC-{rid[1:]}"
        return "https://rules.sonarsource.com/"
    if source == "bandit" and rule.upper().startswith("B"):
        return f"https://bandit.readthedocs.io/en/latest/plugins/index.html#{rule.lower()}"
    return ""


def cwe_url(cwe):
    try:
        n = int(str(cwe).strip())
    except (TypeError, ValueError):
        return ""
    return f"https://cwe.mitre.org/data/definitions/{n}.html" if n > 0 else ""


# --- Recomendaciones: derivadas de lo que realmente apareció ----------------
_RULE_ADVICE = [
    (("secrets:", "S6334", "S6708", "S2068", "S6418"),
     "Hay credenciales en archivos versionados. Rotalas primero — corregir el archivo no "
     "revoca una clave ya expuesta, y si está en el historial de git sigue siendo "
     "recuperable. Después movelas a un gestor de secretos (Secret Manager, Vault, "
     "Sealed Secrets) y sumá un escaneo de secretos al pre-commit."),
    (("S6472",),
     "Los <code>ARG</code> de Docker quedan en el historial de capas de la imagen. Para "
     "secretos en build usá <code>--mount=type=secret</code> de BuildKit."),
    (("S2245",),
     "Se usa un generador pseudoaleatorio no criptográfico. Para tokens, identificadores de "
     "sesión o cualquier valor que deba ser impredecible, usá la API criptográfica de la "
     "plataforma."),
    (("S6437",),
     "Credenciales embebidas en el código. Movelas a variables de entorno o a un gestor de "
     "secretos."),
    (("kubernetes:",),
     "Endurecé los manifiestos: límites de CPU y memoria, <code>readOnlyRootFilesystem</code>, "
     "usuario no root y capacidades mínimas. Un contenedor sin límites es un vector de "
     "denegación de servicio."),
]


def advice_for(findings, key):
    """Consejos disparados por las reglas que efectivamente aparecieron."""
    seen, out = set(), []
    rules = " ".join(f.get("rule", "") or "" for f in findings)
    for needles, text in _RULE_ADVICE:
        if any(n in rules for n in needles) and text not in seen:
            seen.add(text)
            out.append(text)

    sevs = severity_totals(findings)
    if key == "sca" and (sevs["crit"] or sevs["high"]):
        out.append(
            "Priorizá las dependencias con fix publicado: son las de menor costo y mayor "
            "retorno. Para las que no lo tienen, evaluá si el código realmente ejecuta la "
            "función afectada antes de bloquear un release. Automatizá la vigilancia con "
            "Dependabot o Renovate para que el árbol no vuelva a envejecer.")
    if key == "dast" and zap_ran():
        out.append(
            "El scan fue <em>baseline</em>: recorre sin autenticarse y no ejecuta ataques "
            "activos. La superficie autenticada —que suele ser la que importa— queda sin "
            "probar hasta que se le den credenciales y la especificación OpenAPI.")
    if key == "owasp":
        out.append(
            "Los controles de autorización (BOLA, BFLA, mass assignment) no se detectan "
            "automáticamente: requieren leer el código y contrastarlo con el modelo de "
            "negocio. Conviene fijarlos con tests de integración que intenten acceder a "
            "recursos ajenos y esperen un 403.")
    if key == "sast":
        smells = len((sonar_issue_list().get("CODE_SMELL") or []))
        if smells > 500:
            out.append(
                f"Los {smells} code smells no son vulnerabilidades, pero la duplicación y la "
                "complejidad alta encarecen cada corrección de seguridad futura. Conviene fijar "
                "un umbral en el quality gate para código nuevo antes que intentar saldar la "
                "deuda existente de una vez.")
    return out


def analysis_block(key, results_html, findings):
    """Estructura fija para las pestañas de análisis: el lector la aprende una vez."""
    meta = ANALYSIS[key]
    tools = " · ".join(
        f'<a href="{esc(u)}" target="_blank" rel="noopener">{esc(n)}</a>'
        for n, u in meta["tools"])
    out = [callout(
        f"<p>{meta['what']}</p>"
        f"<p><strong>Qué no cubre:</strong> {meta['limit']}</p>"
        f"<p><strong>Documentación oficial:</strong> {tools}</p>",
        "neutral", f"Qué es {meta['label']}")]

    out.append(f'<h3><span class="s-num">1</span> Resultados</h3>{results_html}')

    subset = [f for f in MERGED_ROWS if f.get("source") in meta["sources"]]
    if subset:
        out.append('<h3><span class="s-num">2</span> Plan de remediación de este análisis</h3>')
        for prio, label in (("P1", "P1 — inmediato"), ("P2", "P2 — planificado"),
                            ("P3", "P3 — backlog")):
            bucket = [r for r in subset if r.get("priority") == prio]
            if bucket:
                out.append(f'<p class="sub-lbl">{label} · {len(bucket)}</p>'
                           + remediation_rows_html(bucket[:60]))
                if len(bucket) > 60:
                    out.append(f'<p class="more-note">y {len(bucket)-60} más — '
                               "el listado completo está en la pestaña Plan de remediación.</p>")

    tips = advice_for(findings, key)
    if tips:
        body = "<ul>" + "".join(f"<li>{t}</li>" for t in tips) + "</ul>"
        out.append(f'<h3><span class="s-num">3</span> Recomendación</h3>'
                   + callout(body, "info", "Buenas prácticas para este análisis"))

    files = [f for f in meta["files"] if (OUT_DIR / f).exists()]
    if files:
        links = " · ".join(
            f'<a href="{esc(f)}">{esc(f)}</a>' for f in files)
        out.append(callout(
            f"<p>Salida sin procesar de la herramienta: {links}</p>", "neutral",
            "Reporte original"))
    return "".join(out)


kinds = set(inventory.get("kinds") or [])
web_owasp = owasp.get("web") or []
api_owasp = owasp.get("api") or []

if kinds == {"serverless"}:
    web_section = callout(
        "<p>No aplica: el inventario detectó solo componentes serverless. "
        "La superficie relevante está en el API Top 10 y en la revisión de handlers.</p>",
        "neutral")
else:
    web_section = owasp_table(web_owasp, "Sin mapeo OWASP web: las herramientas no aportaron "
                                         "hallazgos con CWE asociable.")
api_section = owasp_table(api_owasp, "Sin mapeo OWASP API.")

zap_empty = ("No se ejecutó ZAP (sin URL HTTP o Docker no disponible). "
             "El análisis estático sigue siendo válido.")


def dast_results():
    """Cada objetivo con su etiqueta: mezclar un scan local con uno productivo
    sin distinguirlos llevaría a leer mal el riesgo."""
    out = [zap_targets_html()]
    targets = []
    if zap_web:
        targets.append(("Objetivo web", zap_cfg.get("web_url", ""), zap_web, False))
    if zap_api:
        targets.append(("Objetivo API", zap_cfg.get("api_url", ""), zap_api, False))
    if zap and not (zap_web or zap_api):
        targets.append(("Objetivo", zap_cfg.get("target_url", ""), zap, False))
    for extra in sorted(OUT_DIR.glob("zap-dast-*.json")):
        if extra.name in ("zap-dast-web.json", "zap-dast-api.json", "zap-dast-report.json"):
            continue
        doc = load_json(extra.name)
        if not doc:
            continue
        host = ""
        for site in doc.get("site", []):
            host = site.get("@name", "") or host
        is_prod = "prod" in extra.name.lower()
        targets.append((f"Objetivo adicional — {extra.stem}", host, doc, is_prod))

    for label, url, doc, is_prod in targets:
        head = f'<h4>{esc(label)}'
        if url:
            head += f' <span class="loc">{esc(url)}</span>'
        head += "</h4>"
        out.append(head)
        if is_prod:
            out.append(callout(
                f"<p>Este escaneo se ejecutó contra <strong>un entorno productivo</strong>"
                + (f" (<code>{esc(url)}</code>)" if url else "")
                + ". Queda constancia acá por trazabilidad: escanear producción puede generar "
                "tráfico y registros en sistemas reales, y debe hacerse con autorización "
                "explícita del responsable del servicio.</p>",
                "warn", "Escaneo sobre producción"))
        out.append(zap_table_for(doc, zap_empty))
    return "".join(out)


def sast_results():
    out = [sonar_access_html()]
    buckets = sonar_issue_list()
    vulns = buckets.get("VULNERABILITY") or []
    bugs = buckets.get("BUG") or []
    if vulns or bugs:
        out.append(callout(
            f"<p>SonarQube clasifica sus hallazgos por tipo. Se separan acá porque su campo "
            f"<code>severity</code> mide impacto en <em>mantenibilidad</em>, no en seguridad: "
            f"un <code>CRITICAL</code> puede ser un ternario anidado. "
            f"<strong>{len(vulns)}</strong> vulnerabilidades y <strong>{len(bugs)}</strong> "
            f"bugs alimentan el plan; los code smells no.</p>", "info", "Cómo leer esto"))
    if vulns:
        out.append("<h4>Vulnerabilidades</h4>"
                   + sonar_typed_table(vulns, "Sin vulnerabilidades."))
    if bugs:
        out.append("<h4>Bugs</h4>" + sonar_typed_table(bugs, "Sin bugs."))
    hs = sonar_hotspots if isinstance(sonar_hotspots, list) else (
        (sonar_hotspots or {}).get("hotspots") if isinstance(sonar_hotspots, dict) else None)
    if hs:
        out.append("<h4>Security hotspots</h4>"
                   + sonar_typed_table(hs, "Sin hotspots.", hotspot=True))
    sm = smells_html()
    if sm:
        out.append('<details class="fold"><summary>Deuda técnica — code smells</summary>'
                   + sm + "</details>")
    bt = bandit_table()
    if bandit:
        out.append("<h4>Bandit (Python)</h4>" + bt)
    return "".join(out)


def sca_results():
    out = []
    if npm_audit:
        out.append("<h4>Node.js</h4>" + npm_audit_table())
    if pip_audit:
        out.append("<h4>Python</h4>" + pip_audit_table())
    if not out:
        out.append(callout("<p>No se auditaron dependencias: no se encontró "
                           "<code>package.json</code> ni manifiestos de Python.</p>", "neutral"))
    return "".join(out)


def owasp_results():
    return ("<h4>API Security Top 10 (2023)</h4>" + api_section
            + "<h4>Top 10 web (2021)</h4>" + web_section)


TABS = [
    Tab("resumen", "Resumen",
        verdict_html()
        + '<h3><span class="s-num">1</span> Cobertura por análisis</h3>' + summary_table()
        + '<h3><span class="s-num">2</span> Alcance y limitaciones</h3>' + scope_html()
        + '<h3><span class="s-num">3</span> Contexto del proyecto</h3>'
        + inventory_html() + prereqs_html()),
    Tab("sast", "SAST",
        analysis_block("sast", sast_results(),
                       [f for f in FINDINGS if f["source"] in ("sonar", "bandit")])),
    Tab("sca", "SCA",
        analysis_block("sca", sca_results(),
                       [f for f in FINDINGS if f["source"] in ("npm", "pip")])),
    Tab("dast", "DAST",
        analysis_block("dast", dast_results(),
                       [f for f in FINDINGS if f["source"] == "zap"])),
    Tab("owasp", "OWASP",
        analysis_block("owasp", owasp_results(),
                       [f for f in FINDINGS if f["source"] == "owasp"])),
    Tab("plan", "Plan de remediación", remediation_full_html()),
    Tab("anexos", "Anexos", annexes_html() + methodology_html()),
]

FONT_LINK = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
    'family=Poppins:wght@600;700&family=Montserrat:wght@400;500;600&display=swap">'
)

SCRIPT = """
(function(){
  var root=document.documentElement;
  var print=document.getElementById('print');
  if(print){print.addEventListener('click',function(){window.print();});}

  // Filtro por severidad: alterna una clase por fila. Sin JS, todo queda visible.
  var active=new Set();
  var btns=[].slice.call(document.querySelectorAll('.f-btn'));
  function apply(){
    var q=(document.getElementById('q')||{}).value||'';
    q=q.trim().toLowerCase();
    [].forEach.call(document.querySelectorAll('tbody tr[data-sev]'),function(tr){
      var okSev=!active.size||active.has(tr.getAttribute('data-sev'));
      var okQ=!q||(tr.getAttribute('data-q')||'').indexOf(q)>-1;
      tr.classList.toggle('is-dim',!okSev&&okQ);
      tr.classList.toggle('is-hidden',!okQ||(!okSev&&!!q));
    });
  }
  btns.forEach(function(b){
    b.addEventListener('click',function(){
      var s=b.getAttribute('data-sev');
      if(active.has(s)){active.delete(s);b.setAttribute('aria-pressed','false');}
      else{active.add(s);b.setAttribute('aria-pressed','true');}
      apply();
    });
  });
  var q=document.getElementById('q');
  if(q){q.addEventListener('input',apply);}


  // Pestañas: patrón APG. El panel activo va al hash para poder enlazarlo.
  var btns2=[].slice.call(document.querySelectorAll('.tab-btn'));
  var panels=[].slice.call(document.querySelectorAll('.tab-panel'));
  function showTab(id,focus){
    btns2.forEach(function(b){
      var on=b.id==='tb-'+id;
      b.setAttribute('aria-selected',on?'true':'false');
      b.tabIndex=on?0:-1;
      if(on&&focus)b.focus();
    });
    panels.forEach(function(pn){
      var on=pn.id==='tp-'+id;
      pn.classList.toggle('is-active',on);
      pn.hidden=!on;
    });
    [].forEach.call(document.querySelectorAll('.side nav a,.toc-m nav a'),function(a){
      a.classList.toggle('is-active',a.getAttribute('data-tab')===id);
    });
    apply();
  }
  btns2.forEach(function(b,i){
    b.addEventListener('click',function(){
      var id=b.id.slice(3);
      showTab(id);
      if(history.replaceState)history.replaceState(null,'','#'+id);
    });
    b.addEventListener('keydown',function(e){
      var d=e.key==='ArrowRight'?1:(e.key==='ArrowLeft'?-1:0);
      if(!d)return;
      e.preventDefault();
      showTab(btns2[(i+d+btns2.length)%btns2.length].id.slice(3),true);
    });
  });
  [].forEach.call(document.querySelectorAll('.side nav a,.toc-m nav a'),function(a){
    a.addEventListener('click',function(e){
      var id=a.getAttribute('data-tab');
      if(!id)return;
      e.preventDefault();
      showTab(id);
      if(history.replaceState)history.replaceState(null,'','#'+id);
      document.querySelector('.tabbar').scrollIntoView({block:'start'});
    });
  });
  var initial=(location.hash||'').slice(1);
  if(initial&&document.getElementById('tp-'+initial))showTab(initial);
  else if(btns2.length)showTab(btns2[0].id.slice(3));

  // Al imprimir hay que mostrar todo; después se restaura la pestaña activa.
  window.addEventListener('beforeprint',function(){
    panels.forEach(function(pn){pn.dataset.wasHidden=pn.hidden?'1':'';pn.hidden=false;});
  });
  window.addEventListener('afterprint',function(){
    panels.forEach(function(pn){pn.hidden=pn.dataset.wasHidden==='1';});
  });

  // Los <details> colapsables (deuda técnica) se abren al imprimir.
  var folds=[].slice.call(document.querySelectorAll('details.fold'));
  var wasClosed=[];
  window.addEventListener('beforeprint',function(){
    wasClosed=folds.filter(function(d){return !d.open;});
    wasClosed.forEach(function(d){d.open=true;});
  });
  window.addEventListener('afterprint',function(){
    wasClosed.forEach(function(d){d.open=false;});
    wasClosed=[];
  });
})();
"""

html = (
    "<!DOCTYPE html>\n"
    '<html lang="es"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1">'
    f"<title>Análisis de Seguridad — {esc(PROJECT_NAME)}</title>"
    f'<meta name="description" content="{esc(REPORT_TYPE)} — {esc(PROJECT_NAME)}, '
    f'{esc(ANALYSIS_DATE)}">'
    + '<script>document.documentElement.classList.add("js-on")</script>'
    + FONT_LINK
    + "<style>" + css_root() + BASE_CSS + "</style></head><body>"
    + '<div class="shell">'
    + sidebar_html(TABS)
    + '<main class="main">'
    + masthead_html()
    + head_html()
    + toolbar_html()
    + '<div class="wrap">'
    + '<details class="toc-m no-print"><summary>' + icon("list")
    + "Índice del reporte</summary>" + render_nav(TABS) + "</details>"
    + render_tabs(TABS)
    + "</div>"
    + footer_html()
    + "</main></div>"
    + "<script>" + SCRIPT + "</script>"
    + "</body></html>"
)

out_file = OUT_DIR / (
    cfg.get("output", {}).get("report_filename", "security-report-completo.html")
    if cfg
    else "security-report-completo.html"
)
out_file.write_text(html, encoding="utf-8")
print(f"[OK] {out_file} ({out_file.stat().st_size / 1024:.1f} KB)")
print(f"     {len(FINDINGS)} hallazgos · P1={P1_COUNT} P2={P2_COUNT} · "
      f"{len(TABS)} pestañas")
