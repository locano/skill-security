#!/usr/bin/env python3
"""
generate-report-template.py — Generador GENÉRICO de reporte de seguridad HTML.

A diferencia de security-reports/generate-report.py (que tiene los hallazgos
de ESTE proyecto hardcodeados), este script construye el reporte leyendo:
  - security-reports/security.config.yml   (branding, nombre de proyecto)
  - security-reports/bandit-report.json     (SAST Python, opcional)
  - security-reports/npm-audit-report.json  (SCA Node, opcional)
  - security-reports/pip-audit-report.json  (SCA Python, opcional)
  - security-reports/zap-dast-report.json   (DAST, opcional)
  - security-reports/sonarqube-summary.json (SAST, opcional — ver nota abajo)

Cualquier archivo que no exista simplemente se omite de esa sección del reporte.

Uso:
    python3 generate-report-template.py [output_dir]

Nota SonarQube: no hay un export JSON "summary" estándar de un solo request;
este script espera un JSON simple con la forma:
  {"bugs": N, "vulnerabilities": N, "code_smells": N, "security_hotspots": N,
   "quality_gate": "OK"|"ERROR", "coverage": "12.3", "duplicated_lines_density": "4.5"}
Puedes generarlo con: curl de /api/measures/component (ver README del skill).
"""

import json
import os
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
            return yaml.safe_load(f)
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

PROJECT_NAME = project.get("name", "Proyecto")
BRANDING_ON = bool(branding.get("enabled", False))
COLOR_PRIMARY = branding.get("primary_color", "#1a1a2e") if BRANDING_ON else "#1a1a2e"
COLOR_SECONDARY = branding.get("secondary_color", "#16213e") if BRANDING_ON else "#16213e"
COLOR_ACCENT = branding.get("accent_color", "#0f9d58") if BRANDING_ON else "#0f9d58"
FONT_FAMILY = branding.get("font_family", "Arial, sans-serif") if BRANDING_ON else "Arial, sans-serif"
COMPANY_NAME = branding.get("company_name", "") if BRANDING_ON else ""

bandit = load_json("bandit-report.json")
npm_audit = load_json("npm-audit-report.json")
pip_audit = load_json("pip-audit-report.json")
zap = load_json("zap-dast-report.json")
sonar = load_json("sonarqube-summary.json")

date_str = datetime.now().strftime("%d/%m/%Y")


# ---------- Bandit ----------
def bandit_rows():
    if not bandit:
        return "<tr><td colspan='4'>No se ejecutó Bandit (sin archivos Python o script omitido).</td></tr>"
    results = bandit.get("results", [])
    if not results:
        return "<tr><td colspan='4'>Bandit no encontró hallazgos.</td></tr>"
    rows = []
    for r in results[:100]:
        sev = r.get("issue_severity", "LOW")
        rows.append(
            f"<tr><td>{r.get('test_id','')}</td><td>{r.get('filename','')}:{r.get('line_number','')}</td>"
            f"<td><span class='sev s-{sev.lower()}'>{sev}</span></td>"
            f"<td>{r.get('issue_text','')[:120]}</td></tr>"
        )
    return "\n".join(rows)


def bandit_counts():
    if not bandit:
        return {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in bandit.get("results", []):
        sev = r.get("issue_severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------- npm / pip audit ----------
def npm_counts():
    if not npm_audit:
        return {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    vulns = npm_audit.get("vulnerabilities", {})
    counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    for v in vulns.values():
        sev = v.get("severity", "low")
        if sev in counts:
            counts[sev] += 1
    return counts


def pip_audit_rows():
    if not pip_audit:
        return "<tr><td colspan='3'>No se ejecutó pip-audit.</td></tr>"
    deps = pip_audit.get("dependencies", pip_audit if isinstance(pip_audit, list) else [])
    rows = []
    for dep in deps:
        vulns = dep.get("vulns", []) if isinstance(dep, dict) else []
        for v in vulns:
            rows.append(
                f"<tr><td>{dep.get('name','')} {dep.get('version','')}</td>"
                f"<td>{v.get('id','')}</td><td>{', '.join(v.get('fix_versions', []) or ['Sin fix'])}</td></tr>"
            )
    if not rows:
        return "<tr><td colspan='3'>Sin vulnerabilidades en dependencias Python.</td></tr>"
    return "\n".join(rows)


# ---------- ZAP ----------
def zap_counts():
    if not zap:
        return {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "Informational").split(" ")[0]
            counts[risk] = counts.get(risk, 0) + 1
    return counts


def zap_rows():
    if not zap:
        return "<tr><td colspan='3'>No se ejecutó ZAP (definir target_url en security.config.yml).</td></tr>"
    rows = []
    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "Informational").split(" ")[0].lower()
            rows.append(
                f"<tr><td>{alert.get('name','')}</td>"
                f"<td><span class='sev s-{risk}'>{alert.get('riskdesc','')}</span></td>"
                f"<td>{alert.get('desc','')[:150]}</td></tr>"
            )
    if not rows:
        return "<tr><td colspan='3'>ZAP no encontró alertas.</td></tr>"
    return "\n".join(rows)


bandit_c = bandit_counts()
npm_c = npm_counts()
zap_c = zap_counts()

html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Análisis de Seguridad — {PROJECT_NAME}</title>
<style>
  body {{ font-family: {FONT_FAMILY}; color: #222; line-height: 1.55; max-width: 980px; margin: 0 auto; padding: 30px; }}
  h1 {{ color: {COLOR_PRIMARY}; border-bottom: 3px solid {COLOR_ACCENT}; padding-bottom: 10px; }}
  h2 {{ color: {COLOR_SECONDARY}; margin-top: 34px; border-left: 4px solid {COLOR_ACCENT}; padding-left: 10px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #ddd; padding: 7px 10px; text-align: left; vertical-align: top; }}
  th {{ background: {COLOR_PRIMARY}; color: white; }}
  tr:nth-child(even) {{ background: #f7f7f9; }}
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; }}
  .s-critical, .s-crit, .s-high, .s-alto {{ background: #fde2e1; color: #a3231f; border: 1px solid #f5b7b5; }}
  .s-medium, .s-med, .s-moderate {{ background: #fff2cc; color: #8a6d00; border: 1px solid #ffe08a; }}
  .s-low, .s-bajo {{ background: #e2f0fb; color: #1a5276; border: 1px solid #aed6f1; }}
  .s-informational, .s-nd {{ background: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }}
  .meta {{ font-size: 12px; color: #666; margin-bottom: 20px; }}
  .note {{ padding: 10px 14px; border-radius: 4px; margin: 12px 0; font-size: 13px; }}
  .note.info {{ background: #e2f0fb; border-left: 4px solid #1a5276; }}
</style>
</head>
<body>

<h1>Análisis de Seguridad — {PROJECT_NAME}</h1>
<div class="meta">
  {"Generado para " + COMPANY_NAME + " · " if COMPANY_NAME else ""}Fecha: {date_str} &nbsp;·&nbsp;
  Generado por skill <code>/security-scan</code> de Claude Code
</div>

<h2>1. Resumen Ejecutivo</h2>
<table>
  <tr><th>Categoría</th><th>Herramienta</th><th>Alto/Crítico</th><th>Medio</th><th>Bajo</th></tr>
  <tr><td>SAST — Python</td><td>Bandit</td>
      <td>{bandit_c['HIGH']}</td><td>{bandit_c['MEDIUM']}</td><td>{bandit_c['LOW']}</td></tr>
  <tr><td>SCA — Node.js</td><td>npm audit</td>
      <td>{npm_c['critical'] + npm_c['high']}</td><td>{npm_c['moderate']}</td><td>{npm_c['low']}</td></tr>
  <tr><td>DAST</td><td>OWASP ZAP</td>
      <td>{zap_c['High']}</td><td>{zap_c['Medium']}</td><td>{zap_c['Low']}</td></tr>
</table>

<h2>2. SAST — Bandit (Python)</h2>
<table>
  <tr><th>Regla</th><th>Ubicación</th><th>Severidad</th><th>Descripción</th></tr>
  {bandit_rows()}
</table>

<h2>3. SCA — Dependencias Python (pip-audit)</h2>
<table>
  <tr><th>Paquete</th><th>CVE/ID</th><th>Fix disponible</th></tr>
  {pip_audit_rows()}
</table>

<h2>4. DAST — OWASP ZAP</h2>
<div class="note info">
  Target escaneado: <code>{(cfg.get('zap', {}) or {}).get('target_url', 'no definido')}</code>
</div>
<table>
  <tr><th>Alerta</th><th>Riesgo</th><th>Descripción</th></tr>
  {zap_rows()}
</table>

<h2>5. Notas</h2>
<p>Este reporte fue generado automáticamente por el skill <code>/security-scan</code>.
Para hallazgos que requieran contexto de negocio (falsos positivos, comportamiento esperado),
documentarlos manualmente en una sección de "Excepciones validadas" antes de enviar a revisión.</p>

</body>
</html>
"""

out_file = OUT_DIR / (cfg.get("output", {}).get("report_filename", "security-report-completo.html")
                       if cfg else "security-report-completo.html")
out_file.write_text(html, encoding="utf-8")
print(f"[OK] {out_file} ({out_file.stat().st_size / 1024:.1f} KB)")
