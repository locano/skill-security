# Security Scan — SAST + SCA + DAST

Plugin: `/security-scan`. Los scripts corren desde el plugin; el cwd es el
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

## Matriz

| Tipo | SAST | ZAP | OWASP |
|---|---|---|---|
| Web | cwd | `--web-url` | Top 10 2021 |
| API | cwd | `--api-url` / OpenAPI | API Top 10 2023 |
| Serverless | cwd | solo si hay URL HTTP | handlers (revisión) |

No se lintéa el layout de carpetas. Inventario descriptivo en `inventory.json`.

## SonarQube

Dashboard: `http://localhost:9000/dashboard?id=<key>`

Login (el script y el HTML lo muestran siempre):

- Usuario: `admin`
- Password: contenido de `security-reports/.sonar-admin`
- Si ese archivo no existe: `Security_Scan_<año>!` (ej. `Security_Scan_2026!`)
- Primera vez, antes de que el skill cambie la clave: `admin` / `admin`

Se escribe en `sonar-status.json` (`login`, `password`, `dashboard_url`)
aunque el scanner falle.

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
