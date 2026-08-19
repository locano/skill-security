# Security Scan — SAST + SCA + DAST

Plugin: `/skill-security-scan`. Los scripts corren desde el plugin; el cwd es el
repo a analizar.

## Uso

Desde la raíz del destino:

```bash
bash /ruta/al/plugin/scripts/security/run-scan.sh \
  --project-name "Mi app" \
  [--project-key mi-app] \
  [--web-url http://localhost:3000] \
  [--api-url http://localhost:8000] \
  [--target-url http://localhost:3000] \
  [--openapi openapi.yaml] \
  [--scan-type baseline] \
  [--only sast|sonar|zap|report] \
  [--one-by-one]
```

Con poco disco (menos de 5 GB en el cwd) `run-scan.sh` pasa solo a **1 por 1**:
no baja Sonar y ZAP juntos. `--only` corre un scanner y regenera el HTML
con lo que haya (se puede repetir). `--one-by-one` fuerza ese orden.

`--target-url` es un solo target (compat, escribe `zap-dast-report.json`).
ZAP vive en Docker: si pasás `http://localhost:4000`, por dentro usa
`host.docker.internal:4000` para llegar a **tu proceso en la Mac**. Es la
misma API/web; no hace falta que esté en Docker. Los reportes se reescriben
otra vez a `localhost` para que no parezca otro host.
`--web-url` + `--api-url` generan `zap-dast-web.json` y `zap-dast-api.json`.
Sin URL, ZAP se omite; SAST de toda la carpeta sigue.

`run-scan.sh` imprime `=== [1/6] … ===`. El skill de Claude **no** debe
usarlo en silencio: corre cada script y avisa al usuario entre fases.

## Estructura

Cada carpeta es un tipo de análisis distinto; el número es el orden de ejecución.

| Carpeta | Qué análisis hace | Mira… |
|---|---|---|
| `1-preflight/` | Reconocimiento: qué es el repo y qué herramientas hay | el repo y la máquina |
| `2-sast/` | **SAST** — análisis estático | el código fuente, sin ejecutarlo |
| `3-sca/` | **SCA** — composición de software | las dependencias que instalaste |
| `4-dast/` | **DAST** — análisis dinámico | la app corriendo, vía HTTP |
| `5-report/` | Correlación OWASP y reporte final | los JSON de las fases anteriores |

`run-scan.sh` queda en la raíz porque es el punto de entrada: llama a todos los
demás en ese orden. Cada script también corre suelto, pasándole el output dir.

La diferencia entre SAST y SCA es la que más se confunde: **SAST busca bugs en
el código que vos escribiste; SCA busca CVE conocidos en el código que
importaste.** Por eso Bandit está en `2-sast/` y `npm audit`/`pip-audit` en
`3-sca/`, aunque antes vivían en el mismo archivo.

## Matriz

| Tipo | SAST | ZAP | OWASP |
|---|---|---|---|
| Web | cwd | `--web-url` | Top 10 2021 |
| API | cwd | `--api-url` / OpenAPI | API Top 10 2023 |
| Serverless | cwd | solo si hay URL HTTP | handlers (revisión) |

No se lintéa el layout de carpetas. Inventario descriptivo en `inventory.json`.

## Artefactos

Todo queda en `security-reports/` (en `.gitignore`: puede traer secretos).

| Archivo | Lo escribe | Contiene |
|---|---|---|
| `security-report-completo.html` | `5-report/generate-report-template.py` | El reporte: web para revisar, Cmd+P para PDF |
| `bandit-report.json` | `2-sast/run-bandit.sh` | Hallazgos Python, con `code` y `more_info` |
| `npm-audit-report.json` / `pip-audit-report.json` | `3-sca/run-sca.sh` | Dependencias vulnerables (npm, pnpm o yarn) |
| `zap-dast-{report,web,api}.{html,json}` | `4-dast/run-zap.sh` | Reporte nativo de ZAP, con instancias y solución |
| `sonarqube-summary.json` | `2-sast/run-sonarqube.sh` | Contadores y quality gate |
| `sonarqube-issues.json` / `sonarqube-hotspots.json` | `2-sast/run-sonarqube.sh` | Detalle por issue, consultable sin el contenedor |
| `owasp-summary.json` | `5-report/map-owasp.py` | Mapeo contra Top 10 y API Top 10 |
| `owasp-review.json` | el agente | Revisión manual de lo que las tools no ven |
| `remediation-plan.json` | el agente | Acción, responsable, fecha e impacto por hallazgo (opcional) |
| `assessment.json` | el agente | Veredicto ejecutivo y alcance/limitaciones (opcional) |
| `inventory.json` / `prereqs.json` | inventario / preflight | Contexto del scan |

El reporte enlaza todos estos archivos en su última sección con rutas
relativas: comprimís la carpeta y sigue navegable.

### Gestores de paquetes Node

`run-sca.sh` elige el comando según el lockfile: `pnpm-lock.yaml` → `pnpm audit`,
`yarn.lock` → `yarn npm audit`, si no `npm audit`. **El formato de salida difiere**:
npm emite `{"vulnerabilities": {paquete}}` y pnpm `{"advisories": {id}}`. El
generador entiende los dos; usar el comando equivocado devolvía un informe vacío
que parecía "sin hallazgos".

### `assessment.json`

Opcional. Contiene el veredicto ejecutivo (`verdict`: `status`, `summary`,
`reasons`, `to_change`) y el alcance (`scope`: `tested`, `not_tested`). Sin él,
el veredicto se deriva de los hallazgos P1 y el alcance de los datos del scan.

### `remediation-plan.json`

Opcional. Sin él la sección de plan se genera igual, clasificando por severidad
(P1 crítico/alto, P2 medio, P3 bajo/calidad). Con él agregás acción, responsable
y fecha. `id` exacto pisa todo incluida la prioridad; `match` aplica a varios
pero no pisa un `id`; `hide` saca una fila; `extra[]` suma hallazgos manuales.
Un `id` que ya no existe se marca como huérfano en vez de descartarse. Los
formatos de `id` están en `SKILL.md`.

## SonarQube

Dashboard: `http://localhost:9000/dashboard?id=<key>`

Login (el script y el HTML lo muestran siempre):

- Usuario: `admin`
- Password: contenido de `security-reports/.sonar-admin`
- Si ese archivo no existe: el store global
  `~/.config/skill-security/sonar-admin-<puerto>`
- Si tampoco: `Security_Scan_<año>!` (ej. `Security_Scan_2026!`)
- Primera vez, antes de que el skill cambie la clave: `admin` / `admin`

### Reutilizar un SonarQube existente

El contenedor (`sonarqube-security-scan`) es **uno por máquina**, pero
`.sonar-admin` vive dentro de cada proyecto. Por eso la password se guarda
además en un store global: sin él, el segundo proyecto que reutiliza el mismo
SonarQube no la encuentra, cae a `admin/admin` y falla.

`setup-sonarqube.sh` prueba las credenciales en este orden, y usa la primera
que autentique:

1. `SONAR_ADMIN_PASSWORD` (si está definida)
2. `security-reports/.sonar-admin` del proyecto actual
3. `~/.config/skill-security/sonar-admin-<puerto>` (store global)
4. `Security_Scan_<año>!`
5. `admin` / `admin` — contenedor virgen; si funciona, rota a la del punto 1 o 4

Si ninguna sirve, no adivina: aborta indicando cómo reintentar.

```bash
# si sabés la password
SONAR_ADMIN_PASSWORD='tu-password' bash run-sonarqube.sh <key> "<nombre>"

# si la perdiste: empezar limpio (borra el historial de análisis)
docker rm -f sonarqube-security-scan
```

Se escribe en `sonar-status.json` (`login`, `password`, `dashboard_url`)
aunque el scanner falle.

Ese dashboard es **local y temporal**: muere con el contenedor y escucha en
`localhost`, así que no le sirve a nadie más. Por eso `run-sonarqube.sh` exporta
además el detalle por issue a `sonarqube-issues.json` y `sonarqube-hotspots.json`
(paginado, tope 10.000). Si el export falla, escribe una lista vacía y el scan
sigue: nunca aborta por eso.

Si el dashboard dice “Main Branch is not analyzed yet”, el servidor está UP
pero `sonar-scanner` no subió el análisis (en monorepos JS/TS suele ser falta
de RAM en el bridge de Node). El log queda en
`security-reports/sonar-scanner.log`. El script pide 2G Java + 4G Node y
excluye `node_modules`, `.pnpm`, `dist`, `.next`, etc.

## Requisitos

| Herramienta | Obligatorio |
|---|---|
| `python3` + `pyyaml` | Sí |
| `docker` | No (sin Docker: Bandit/SCA) |
| `jq`, `curl` | SonarQube |

## Guardrails

- No `npm audit fix` sin confirmar.
- No active scan a producción.
- No commit de `security-reports/` sin pedido.
