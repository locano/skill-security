#!/usr/bin/env python3
"""Genera security-report-completo.html desde los JSON del scan."""

import json
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
zap_web = load_json("zap-dast-web.json")
zap_api = load_json("zap-dast-api.json")
sonar = load_json("sonarqube-summary.json")
sonar_status = load_json("sonar-status.json") or {}
prereqs = load_json("prereqs.json")
inventory = load_json("inventory.json") or {}
owasp = load_json("owasp-summary.json") or {}

date_str = datetime.now().strftime("%d/%m/%Y")
zap_cfg = cfg.get("zap") or {}


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
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if not bandit:
        return counts
    for r in bandit.get("results", []):
        sev = r.get("issue_severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def npm_counts():
    counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    if not npm_audit:
        return counts
    for v in (npm_audit.get("vulnerabilities") or {}).values():
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


def iter_zap_alerts(*docs):
    for doc in docs:
        if not doc:
            continue
        for site in doc.get("site", []):
            for alert in site.get("alerts", []):
                yield alert


def zap_counts():
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for alert in iter_zap_alerts(zap, zap_web, zap_api):
        risk = alert.get("riskdesc", "Informational").split(" ")[0]
        counts[risk] = counts.get(risk, 0) + 1
    return counts


def zap_rows_from(doc, empty_msg):
    if not doc:
        return f"<tr><td colspan='3'>{empty_msg}</td></tr>"
    rows = []
    for alert in iter_zap_alerts(doc):
        risk = alert.get("riskdesc", "Informational").split(" ")[0].lower()
        rows.append(
            f"<tr><td>{alert.get('name','')}</td>"
            f"<td><span class='sev s-{risk}'>{alert.get('riskdesc','')}</span></td>"
            f"<td>{(alert.get('desc') or '')[:150]}</td></tr>"
        )
    if not rows:
        return "<tr><td colspan='3'>ZAP no encontró alertas.</td></tr>"
    return "\n".join(rows)


def sonar_dashboard():
    if sonar and sonar.get("dashboard_url"):
        return sonar["dashboard_url"]
    if sonar_status.get("dashboard_url"):
        return sonar_status["dashboard_url"]
    if sonar_status.get("url"):
        key = sonar_status.get("project_key") or project.get("key") or ""
        if key:
            return f"{sonar_status['url']}/dashboard?id={key}"
        return sonar_status["url"]
    return "http://localhost:9000"


def sonar_block():
    dash = sonar_dashboard()
    st = sonar_status.get("status") or ("up" if sonar else "unknown")
    reason = sonar_status.get("reason") or sonar_omit_reason()
    login = sonar_status.get("login") or "admin"
    password = sonar_status.get("password") or f"Security_Scan_{datetime.now().year}!"
    pw_file = sonar_status.get("password_file") or "security-reports/.sonar-admin"
    link = (
        f'<p><strong>Abrir SonarQube:</strong> <a href="{dash}">{dash}</a></p>'
        f'<div class="note info"><strong>Login</strong><br/>'
        f'Usuario: <code>{login}</code><br/>'
        f'Password: <code>{password}</code><br/>'
        f'También en <code>{pw_file}</code></div>'
    )
    note = f'<div class="note {"info" if st == "up" and sonar else "warn"}">Estado: <code>{st}</code>. {reason}</div>'
    if not sonar:
        return link + note
    n = {
        "bugs": sonar.get("bugs", 0),
        "vulnerabilities": sonar.get("vulnerabilities", 0),
        "code_smells": sonar.get("code_smells", 0),
        "security_hotspots": sonar.get("security_hotspots", 0),
        "quality_gate": sonar.get("quality_gate", "—"),
        "coverage": sonar.get("coverage", "n/a"),
        "duplicated_lines_density": sonar.get("duplicated_lines_density", "n/a"),
    }
    qg = str(n["quality_gate"])
    qg_class = "s-ok" if qg.upper() == "OK" else ("s-high" if qg.upper() == "ERROR" else "s-nd")
    dup = n["duplicated_lines_density"]
    dup_s = f"{dup}%" if dup not in (None, "", "n/a") else "n/a"
    return f"""
{link}
{note}
<table>
  <tr><th>Métrica</th><th>Valor</th></tr>
  <tr><td>Quality gate</td><td><span class="sev {qg_class}">{qg}</span></td></tr>
  <tr><td>Vulnerabilities</td><td>{n["vulnerabilities"]}</td></tr>
  <tr><td>Bugs</td><td>{n["bugs"]}</td></tr>
  <tr><td>Security hotspots</td><td>{n["security_hotspots"]}</td></tr>
  <tr><td>Code smells</td><td>{n["code_smells"]}</td></tr>
  <tr><td>Coverage</td><td>{n["coverage"]}</td></tr>
  <tr><td>Duplicated lines</td><td>{dup_s}</td></tr>
</table>
"""


def sonar_omit_reason():
    if sonar:
        return "Análisis exportado."
    if prereqs and prereqs.get("docker") != "ok":
        return "Omitido: Docker no está disponible o el daemon no está corriendo."
    if prereqs and not prereqs.get("sonar_ready"):
        return "Omitido: imágenes o herramientas (jq/curl) no listas."
    return "No se ejecutó SonarQube."


def sonar_summary_row():
    dash = sonar_dashboard()
    if not sonar:
        return (
            "<tr><td>SAST — SonarQube</td><td>SonarQube Community</td>"
            f"<td colspan='3'>{sonar_omit_reason()} · <a href='{dash}'>{dash}</a></td></tr>"
        )
    qg = str(sonar.get("quality_gate", "—"))
    qg_class = "s-ok" if qg.upper() == "OK" else ("s-high" if qg.upper() == "ERROR" else "s-nd")
    return (
        "<tr><td>SAST — SonarQube</td><td>SonarQube Community</td>"
        f"<td>{sonar.get('vulnerabilities', 0)} vulns</td>"
        f"<td>{sonar.get('bugs', 0)} bugs / {sonar.get('security_hotspots', 0)} hotspots</td>"
        f"<td><span class='sev {qg_class}'>QG {qg}</span></td></tr>"
    )


def inventory_html():
    kinds = ", ".join(inventory.get("kinds") or ["desconocido"])
    stacks = ", ".join(inventory.get("stacks") or ["—"])
    dirs = ", ".join(inventory.get("top_dirs") or []) or "—"
    specs = ", ".join(inventory.get("openapi") or []) or "ninguno"
    dast = inventory.get("dast_applies")
    dast_msg = "ZAP corre contra las URLs dadas." if dast else "DAST no aplica (sin URL HTTP). SAST de toda la carpeta sí."
    return f"""
<div class="note info">
  <strong>Qué se analizó:</strong> tipos = <code>{kinds}</code> · stacks = <code>{stacks}</code><br/>
  Carpetas top: <code>{dirs}</code> · OpenAPI: <code>{specs}</code><br/>
  {dast_msg}
</div>
"""


def prereqs_html():
    if not prereqs:
        return ""
    docker = prereqs.get("docker", "unknown")
    notes = prereqs.get("notes") or []
    items = "".join(f"<li>{n}</li>" for n in notes)
    return f"""
<div class="note info">
  <strong>Preflight:</strong> Docker = <code>{docker}</code>
  {"<ul>" + items + "</ul>" if items else ""}
</div>
"""


def owasp_table(rows, na_msg):
    if not rows:
        return f"<p>{na_msg}</p>"
    out = ["<table><tr><th>Ítem</th><th>Estado</th><th>Evidencia</th></tr>"]
    for row in rows:
        st = row.get("status", "clear")
        cls = {"hit": "s-high", "clear": "s-ok", "n/a": "s-nd", "fail": "s-high", "pass": "s-ok", "parcial": "s-medium"}.get(st, "s-nd")
        findings = row.get("findings") or []
        ev = "; ".join(f"{f.get('source','')}: {f.get('name','')[:80]}" for f in findings[:5]) or "—"
        rev = row.get("review") or {}
        if rev.get("evidence"):
            ev = f"{ev} · revisión: {rev.get('evidence')}"
        out.append(
            f"<tr><td>{row.get('id','')} {row.get('name','')}</td>"
            f"<td><span class='sev {cls}'>{st}</span></td><td>{ev}</td></tr>"
        )
    out.append("</table>")
    return "\n".join(out)


def zap_targets_note():
    web = zap_cfg.get("web_url") or ""
    api = zap_cfg.get("api_url") or ""
    single = zap_cfg.get("target_url") or "no definido"
    parts = []
    if web:
        parts.append(f"web: <code>{web}</code>")
    if api:
        parts.append(f"api: <code>{api}</code>")
    if not parts:
        parts.append(f"target: <code>{single}</code>")
    return " · ".join(parts)


bandit_c = bandit_counts()
npm_c = npm_counts()
zap_c = zap_counts()
kinds = set(inventory.get("kinds") or [])
web_owasp = owasp.get("web") or []
api_owasp = owasp.get("api") or []
if kinds == {"serverless"}:
    web_section = "<p>N/A — inventario solo serverless. Ver API Top 10 / handlers.</p>"
else:
    web_section = owasp_table(web_owasp, "Sin mapeo OWASP web (no hubo hallazgos de herramientas).")
api_section = owasp_table(api_owasp, "Sin mapeo OWASP API.")

zap_empty = "No se ejecutó ZAP (sin URL HTTP o Docker no disponible). SAST sigue siendo válido."
if zap_web or zap_api:
    zap_tables = ""
    if zap_web:
        zap_tables += "<h3>Web</h3><table><tr><th>Alerta</th><th>Riesgo</th><th>Descripción</th></tr>" + zap_rows_from(zap_web, zap_empty) + "</table>"
    if zap_api:
        zap_tables += "<h3>API</h3><table><tr><th>Alerta</th><th>Riesgo</th><th>Descripción</th></tr>" + zap_rows_from(zap_api, zap_empty) + "</table>"
else:
    zap_tables = "<table><tr><th>Alerta</th><th>Riesgo</th><th>Descripción</th></tr>" + zap_rows_from(zap, zap_empty) + "</table>"

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
  h3 {{ color: {COLOR_SECONDARY}; margin-top: 20px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #ddd; padding: 7px 10px; text-align: left; vertical-align: top; }}
  th {{ background: {COLOR_PRIMARY}; color: white; }}
  tr:nth-child(even) {{ background: #f7f7f9; }}
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; }}
  .s-critical, .s-crit, .s-high, .s-alto, .s-fail {{ background: #fde2e1; color: #a3231f; border: 1px solid #f5b7b5; }}
  .s-medium, .s-med, .s-moderate, .s-parcial {{ background: #fff2cc; color: #8a6d00; border: 1px solid #ffe08a; }}
  .s-low, .s-bajo {{ background: #e2f0fb; color: #1a5276; border: 1px solid #aed6f1; }}
  .s-informational, .s-nd, .s-n\\/a {{ background: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }}
  .s-ok, .s-pass, .s-clear {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
  .meta {{ font-size: 12px; color: #666; margin-bottom: 20px; }}
  .note {{ padding: 10px 14px; border-radius: 4px; margin: 12px 0; font-size: 13px; }}
  .note.info {{ background: #e2f0fb; border-left: 4px solid #1a5276; }}
  .note.warn {{ background: #fff2cc; border-left: 4px solid #8a6d00; }}
</style>
</head>
<body>

<h1>Análisis de Seguridad — {PROJECT_NAME}</h1>
<div class="meta">
  {"Generado para " + COMPANY_NAME + " · " if COMPANY_NAME else ""}Fecha: {date_str} &nbsp;·&nbsp;
  Generado por skill <code>/security-scan</code>
</div>

<h2>1. Qué se analizó</h2>
{inventory_html()}
{prereqs_html()}

<h2>2. Resumen Ejecutivo</h2>
<table>
  <tr><th>Categoría</th><th>Herramienta</th><th>Alto/Crítico</th><th>Medio</th><th>Bajo</th></tr>
  {sonar_summary_row()}
  <tr><td>SAST — Python</td><td>Bandit</td>
      <td>{bandit_c['HIGH']}</td><td>{bandit_c['MEDIUM']}</td><td>{bandit_c['LOW']}</td></tr>
  <tr><td>SCA — Node.js</td><td>npm audit</td>
      <td>{npm_c['critical'] + npm_c['high']}</td><td>{npm_c['moderate']}</td><td>{npm_c['low']}</td></tr>
  <tr><td>DAST</td><td>OWASP ZAP</td>
      <td>{zap_c['High']}</td><td>{zap_c['Medium']}</td><td>{zap_c['Low']}</td></tr>
</table>

<h2>3. SAST — SonarQube</h2>
{sonar_block()}

<h2>4. OWASP Top 10 (web)</h2>
{web_section}

<h2>5. OWASP API Top 10</h2>
{api_section}

<h2>6. SAST — Bandit (Python)</h2>
<table>
  <tr><th>Regla</th><th>Ubicación</th><th>Severidad</th><th>Descripción</th></tr>
  {bandit_rows()}
</table>

<h2>7. SCA — Dependencias Python (pip-audit)</h2>
<table>
  <tr><th>Paquete</th><th>CVE/ID</th><th>Fix disponible</th></tr>
  {pip_audit_rows()}
</table>

<h2>8. DAST — OWASP ZAP</h2>
<div class="note info">{zap_targets_note()}</div>
{zap_tables}

<h2>9. Notas</h2>
<p>SAST cubre toda la carpeta (web, API o serverless). DAST solo corre si hay URL HTTP.
No se valida el orden de carpetas del proyecto destino. OWASP <code>clear</code> significa
sin evidencia automática, no un pass formal. La revisión guiada (si existe) está en
<code>owasp-review.json</code>.</p>

</body>
</html>
"""

out_file = OUT_DIR / (
    cfg.get("output", {}).get("report_filename", "security-report-completo.html")
    if cfg
    else "security-report-completo.html"
)
out_file.write_text(html, encoding="utf-8")
print(f"[OK] {out_file} ({out_file.stat().st_size / 1024:.1f} KB)")
