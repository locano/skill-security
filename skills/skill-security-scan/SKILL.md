---
name: skill-security-scan
description: Análisis de seguridad de cualquier repo (web, API o serverless). SAST de toda la carpeta (Bandit, SCA, SonarQube); DAST (ZAP) solo si hay URL HTTP; checklist OWASP Top 10 y API Top 10. Usar cuando el usuario pida "corre un security scan", "/skill-security-scan", o una auditoría de vulnerabilidades.
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
   - **URLs: preguntá SIEMPRE por las dos, y por separado.** Web y API suelen
     vivir en hosts o puertos distintos (`localhost:3000` y `localhost:8000`,
     o dominios diferentes), así que **nunca asumas que una sirve para las dos**
     ni reutilices la que te dieron para la otra. Preguntá literalmente:
     - ¿URL del front/web? (`--web-url`)
     - ¿URL de la API? (`--api-url`)

     Aceptá que respondan "no tengo" o "no aplica" a cualquiera de las dos: ahí
     esa queda vacía y ZAP simplemente no la escanea. Lo que no vale es no
     preguntar. Si da una sola, **confirmá explícitamente** que la otra no
     existe antes de seguir — es la diferencia entre "no hay front" y "me
     olvidé de mencionarlo".

     localhost vale, pero tiene que estar corriendo. En serverless, si da un
     API Gateway o `sam local`, esa es la API. **Nunca producción sin
     confirmación explícita.**
   - Active scan solo si lo pide (default `baseline`).
   - **Metadatos del documento** (para la portada). Preguntalos de una sola vez,
     y aclarale que puede dejar en blanco lo que no sepa — un campo vacío no se
     muestra, no queda una fila con guión:
     - Preparado por (nombre / equipo)
     - Versión del documento (default `1.0`)
     - Infraestructura (ej. "AWS Lambda + API Gateway")

     El endpoint del encabezado se arma solo con las URLs de arriba; no lo
     vuelvas a preguntar salvo que quiera mostrar algo distinto en la portada.

   Escribí las respuestas en `security-reports/security.config.yml` bajo la clave
   `report:` (`prepared_by`, `document_version`, `infrastructure`, `endpoint`).
   `run-scan.sh` no toca ese bloque, así que sobrevive a cada corrida.

2. **Inventario + preflight** — avisá: “detecto el stack; si falta Docker
   bajo imágenes (~1GB)”.

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/security/1-preflight/collect-inventory.py" security-reports
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/1-preflight/check-prereqs.sh" security-reports [--with-zap]
   ```

   `--with-zap` solo si hay alguna URL. Leé `inventory.json` y decile al
   usuario: tipos (web/api/serverless), stacks, si DAST aplica.

   Si `prereqs.json` tiene `low_disk: true` (o menos de 5 GB libres): **no**
   bajes Sonar y ZAP en el mismo `check-prereqs`. Avisá: “poco disco; corro
   1 scanner por vez para que no fallen todos”. Orden:

   1. SAST (sin imágenes Docker)
   2. `check-prereqs.sh security-reports` (solo Sonar) + `run-sonarqube.sh`
   3. `check-prereqs.sh security-reports --no-sonar --with-zap` + `run-zap.sh`
   4. `map-owasp.py` + HTML (aunque falte una fase)

   Si un pull falla por espacio, seguí con lo que ya hay y generá el HTML.
   El usuario (o vos) también puede repetir:

   ```bash
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-scan.sh" \
     --project-name "<nombre>" --only sast
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-scan.sh" \
     --project-name "<nombre>" --only sonar
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-scan.sh" \
     --project-name "<nombre>" --only zap --web-url <url>
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/run-scan.sh" \
     --project-name "<nombre>" --only report
   ```

   `--one-by-one` en `run-scan.sh` hace el mismo orden (pull por fase).

3. **SAST + SCA local** — “Bandit sobre el código y auditoría de dependencias,
   segundos”. Son dos análisis distintos y ahora dos scripts:

   ```bash
   # SAST: patrones inseguros en el código Python
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/2-sast/run-bandit.sh" security-reports
   # SCA: dependencias de terceros con CVE (pip-audit + npm audit)
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/3-sca/run-sca.sh" security-reports
   ```

   Cada uno se saltea solo si no aplica (sin archivos `.py`, sin manifiestos).

4. **SonarQube** — “primer arranque 1–2 min. Dashboard:
   `http://localhost:9000/dashboard?id=<key>`”. Si `prereqs.json` tiene
   `sonar_ready`, corré:

   ```bash
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/2-sast/run-sonarqube.sh" <key> "<nombre>" security-reports
   ```

   Si falla o no está listo, igual pegá la URL prevista y el `reason` de
   `sonar-status.json`. No es opt-in: se intenta siempre que Docker esté.

5. **ZAP** — solo con URL. Avisá “DAST, varios minutos”.

   ```bash
   # una URL (compat):
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/4-dast/run-zap.sh" <url> baseline security-reports
   # web + api:
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/4-dast/run-zap.sh" --url <web> --kind web --output-dir security-reports --prefix zap-dast-web
   bash "${CLAUDE_PLUGIN_ROOT}/scripts/security/4-dast/run-zap.sh" --url <api> --kind api [--openapi spec] --output-dir security-reports --prefix zap-dast-api
   ```

   Si `inventory.json` trae `openapi` y no dieron spec, usalo. Sin URL:
   “ZAP omitido; SAST válido”.

6. **OWASP + HTML**

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/security/5-report/map-owasp.py" security-reports
   ```

   Después leé handlers/rutas del repo (sin escribir exploits) y completá
   `security-reports/owasp-review.json` solo para ítems que las tools no
   cubren: API1 BOLA, API2 auth, API5 BFLA, API3/mass assignment, API9
   inventory. En serverless, handlers e IAM en código. Forma:

   ```json
   {"items":[{"id":"API1:2023","status":"pass|fail|parcial","evidence":"archivo:línea …"}]}
   ```

   Volvé a correr `map-owasp.py`.

   **Plan de remediación** (opcional pero es lo que más valora quien lee el
   reporte). La sección se genera **siempre**: el generador clasifica cada
   hallazgo en P1 (crítico/alto), P2 (medio) y P3 (bajo/calidad) por severidad.
   Lo que vos agregás es lo que ninguna herramienta sabe: qué hacer, quién y
   cuándo. Escribí `security-reports/remediation-plan.json`:

   ```json
   {
     "defaults": {"owner": "Equipo Backend"},
     "items": [
       {"id": "bandit:B307:app/handler.py:127", "priority": "P1",
        "status": "cerrado", "action": "Reemplazado por _safe_eval() con AST.",
        "owner": "Ludwing", "eta": "2026-08-20",
        "before": "eval(v)", "after": "_safe_eval(v)"},
       {"match": {"source": "npm", "severity": "low"}, "status": "aceptado",
        "action": "Dependencias de build, no llegan a runtime."}
     ],
     "extra": [
       {"id": "manual:jwt-exp", "priority": "P2", "title": "JWT sin expiración",
        "location": "src/auth/token.ts:31", "severity": "medium",
        "action": "Reducir exp a 15 min."}
     ],
     "notes": ["Revisión manual del <fecha>."]
   }
   ```

   Formatos de `id` (salen del propio reporte; son la clave del override):

   | Fuente | `id` |
   |---|---|
   | Bandit | `bandit:{test_id}:{archivo}:{línea}` |
   | npm audit | `npm:{paquete}` |
   | pip-audit | `pip:{paquete}:{vuln_id}` |
   | ZAP | `zap:{web\|api\|single}:{pluginid}` |
   | SonarQube | `sonar:{key del issue}` |
   | OWASP | `owasp:{id}` — ej. `owasp:API1:2023` |

   Reglas: `id` exacto pisa todo, incluida la prioridad (podés subir un medio a
   P1). `match` aplica a varios a la vez pero **nunca** pisa un `id` explícito.
   `hide: true` saca una fila. `extra[]` agrega hallazgos que ninguna herramienta
   detectó. Un `id` que ya no existe **no se descarta**: sale marcado como
   huérfano para que lo actualices. Estados: `abierto`, `cerrado`, `parcial`,
   `planificado`, `aceptado`.

   **Dictamen y alcance** (`security-reports/assessment.json`, opcional). Es lo
   que convierte un volcado de datos en un informe. El reporte se genera igual
   sin esto —el veredicto se deriva de los P1— pero tu lectura vale más:

   ```json
   {
     "verdict": {
       "status": "no-apto | reservas | apto",
       "summary": "Una o dos frases con postura, no un resumen de conteos.",
       "reasons": ["Razón concreta 1", "Razón 2", "Razón 3"],
       "to_change": "Qué tiene que pasar para que el dictamen cambie."
     },
     "scope": {
       "tested": ["Qué se probó realmente"],
       "not_tested": ["Qué quedó afuera y por qué"]
     }
   }
   ```

   Sé honesto en `not_tested`: declarar los límites es lo que separa un informe
   con rigor de uno que se presenta como exhaustivo sin serlo. Si ZAP corrió sin
   credenciales, la superficie autenticada **no** se probó y hay que decirlo.

   **Impacto de negocio** — a cada ítem P1 de `remediation-plan.json` agregale un
   campo `impact` que traduzca el hallazgo a consecuencia real para *este*
   producto: qué dato se expone, a quién, y qué implica. No repitas la
   descripción técnica; el lector ejecutivo ya la tiene arriba.

   ```json
   {"id": "...", "priority": "P1",
    "impact": "Cualquier usuario autenticado puede leer el perfil completo de otro, incluyendo CV y datos de contacto."}
   ```

   Después generá el HTML:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/security/5-report/generate-report-template.py" security-reports
   ```

7. Cierre: HTML en `security-reports/security-report-completo.html`, resumen
   por severidad, **siempre** el link de SonarQube, qué se omitió.

   Decile además que el HTML sirve para las dos cosas: **abrirlo en el navegador**
   para revisar (índice lateral, filtros por severidad, buscador) y **Cmd+P →
   Guardar como PDF** para el documento paginado. Y que la última sección enlaza
   los reportes crudos de cada herramienta, por si quieren consultar un detalle
   puntual.

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
