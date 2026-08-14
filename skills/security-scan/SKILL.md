---
name: security-scan
description: Análisis de seguridad de cualquier repo (web, API o serverless). SAST de toda la carpeta (Bandit, SCA, SonarQube); DAST (ZAP) solo si hay URL HTTP; checklist OWASP Top 10 y API Top 10. Usar cuando el usuario pida "corre un security scan", "/security-scan", o una auditoría de vulnerabilidades.
---

# Security Scan

Scripts en `${CLAUDE_PLUGIN_ROOT}`. El cwd es el repo destino. Solo se escribe
`security-reports/`.

Sirve para **cualquier** proyecto: web, API, serverless o mixto. SAST siempre
mira toda la carpeta. ZAP solo si hay URL HTTP viva. Sin URL el scan es válido.

## Progreso — no un bash silencioso

**No** corras un único `run-scan.sh` y te quedes callado. Ejecutá **fase por
fase** y **antes de cada una** decile al usuario qué va a pasar y cuánto puede
tardar. Si una fase falla, avisá al toque, pegá la URL de Sonar si existe, y
seguí con el resto.

Al terminar **o al fallar** Sonar, pegá siempre este bloque al usuario
(leé `security-reports/sonar-status.json` o `.sonar-admin`; no hagas que
adivine):

```
SonarQube: http://localhost:9000/dashboard?id=<project_key>
Usuario:   admin
Password:  <la de .sonar-admin, o Security_Scan_<año>! si no hay archivo>
```

Si el contenedor es virgen y todavía no corrió el setup: `admin` / `admin`.

## Flujo

1. **Preguntar** (nunca asumir):
   - Nombre del proyecto. Key en kebab-case si no la da.
   - Branding custom o default.
   - URLs **opcionales**: `--web-url` y/o `--api-url` (localhost vale; tiene
     que estar corriendo). Serverless: no insistas en URL; si da API Gateway
     o `sam local`, usala como API. Nunca producción sin confirmación.
   - Active scan solo si lo pide (default `baseline`).

2. **Inventario + preflight** — avisá: “detecto el stack; si falta Docker
   bajo imágenes (~1GB)”.

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/security/collect-inventory.py" security-reports
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/check-prereqs.sh" security-reports [--with-zap]
   ```

   `--with-zap` solo si hay alguna URL. Leé `inventory.json` y decile al
   usuario: tipos (web/api/serverless), stacks, si DAST aplica.

3. **SAST local** — “Bandit / npm audit / pip-audit, segundos”.

   ```bash
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-sast-sca.sh" security-reports
   ```

4. **SonarQube** — “primer arranque 1–2 min. Dashboard:
   `http://localhost:9000/dashboard?id=<key>`”. Si `prereqs.json` tiene
   `sonar_ready`, corré:

   ```bash
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-sonarqube.sh" <key> "<nombre>" security-reports
   ```

   Si falla o no está listo, igual pegá la URL prevista y el `reason` de
   `sonar-status.json`. No es opt-in: se intenta siempre que Docker esté.

5. **ZAP** — solo con URL. Avisá “DAST, varios minutos”.

   ```bash
   # una URL (compat):
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-zap.sh" <url> baseline security-reports
   # web + api:
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-zap.sh" --url <web> --kind web --output-dir security-reports --prefix zap-dast-web
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-zap.sh" --url <api> --kind api [--openapi spec] --output-dir security-reports --prefix zap-dast-api
   ```

   Si `inventory.json` trae `openapi` y no dieron spec, usalo. Sin URL:
   “ZAP omitido; SAST válido”.

6. **OWASP + HTML**

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/security/map-owasp.py" security-reports
   ```

   Después leé handlers/rutas del repo (sin escribir exploits) y completá
   `security-reports/owasp-review.json` solo para ítems que las tools no
   cubren: API1 BOLA, API2 auth, API5 BFLA, API3/mass assignment, API9
   inventory. En serverless, handlers e IAM en código. Forma:

   ```json
   {"items":[{"id":"API1:2023","status":"pass|fail|parcial","evidence":"archivo:línea …"}]}
   ```

   Volvé a correr `map-owasp.py` y después:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/security/generate-report-template.py" security-reports
   ```

7. Cierre: HTML en `security-reports/security-report-completo.html`, resumen
   por severidad, **siempre** el link de SonarQube, qué se omitió.

Atajo CLI (humanos): `run-scan.sh` hace las fases 2–6 con banners. El skill
debe ir fase por fase para que el usuario vea progreso.

## Guardrails

- No `npm audit fix` sin preguntar.
- No ZAP active a producción.
- No commit de `security-reports/` sin pedido explícito.

## Requisitos

| Herramienta | Obligatorio |
|---|---|
| `python3` + `pyyaml` | Sí (HTML) |
| `docker` | No: sin Docker corre Bandit/SCA |
| `jq`, `curl` | Para SonarQube |
