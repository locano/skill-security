#!/usr/bin/env bash
# run-sonarqube.sh — Escanea el directorio actual con sonar-scanner-cli (Docker)
# contra el SonarQube local y escribe sonarqube-summary.json.
#
# Uso:
#   ./run-sonarqube.sh <project_key> <project_name> [output_dir] [port]
#
# Requiere: docker, curl, jq. El cwd debe ser la raíz del repo a analizar.

set -euo pipefail

PROJECT_KEY="${1:?Uso: run-sonarqube.sh <project_key> <project_name> [output_dir] [port]}"
PROJECT_NAME="${2:?Falta project_name}"
OUTPUT_DIR="${3:-security-reports}"
PORT="${4:-9000}"
SCANNER_IMAGE="${SONAR_SCANNER_IMAGE:-sonarsource/sonar-scanner-cli}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[run-sonarqube] $*" >&2; }

write_status() {
  python3 "${SCRIPT_DIR}/write-sonar-status.py" "${OUTPUT_DIR}" "$1" "$2" "http://localhost:${PORT}" "${PROJECT_KEY}" || true
}

mkdir -p "${OUTPUT_DIR}"
export SECURITY_OUTPUT_DIR="${OUTPUT_DIR}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  log "ERROR: Docker no disponible. Omitiendo SonarQube."
  write_status images_missing "Docker no disponible. URL prevista: http://localhost:${PORT}"
  exit 1
fi

if ! docker image inspect "$SCANNER_IMAGE" >/dev/null 2>&1; then
  log "Descargando ${SCANNER_IMAGE}..."
  docker pull "$SCANNER_IMAGE" >&2
fi

SETUP_OUT="$(bash "${SCRIPT_DIR}/setup-sonarqube.sh" "${PROJECT_KEY}" "${PROJECT_NAME}" "${PORT}")"
SONAR_URL="$(printf '%s\n' "$SETUP_OUT" | sed -n 's/^SONAR_URL=//p' | tail -1)"
TOKEN="$(printf '%s\n' "$SETUP_OUT" | sed -n 's/^TOKEN=//p' | tail -1)"

if [ -z "$SONAR_URL" ] || [ -z "$TOKEN" ]; then
  log "ERROR: setup-sonarqube.sh no devolvió SONAR_URL/TOKEN."
  write_status scan_failed "Setup incompleto. Probá ${SONAR_URL:-http://localhost:${PORT}}"
  exit 1
fi

write_status up "Servidor UP. Escaneando… Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
log "Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"

REPO_ROOT="$(pwd)"
SCAN_LOG="${OUTPUT_DIR}/sonar-scanner.log"
EXCLUSIONS="**/node_modules/**,**/.pnpm/**,**/.git/**,**/security-reports/**,**/.venv*/**,**/venv/**,**/dist/**,**/build/**,**/.next/**,**/coverage/**,**/backups/**,**/.vite/**,**/.scannerwork/**,**/*.min.js"

log "Escaneando ${REPO_ROOT} → ${SONAR_URL} (proyecto ${PROJECT_KEY})..."
log "Log del scanner: ${SCAN_LOG}"

# El Node bridge de JS/TS necesita RAM. Sin esto, en monorepos (p. ej. crm-clients)
# el scanner muere y Sonar queda con el proyecto vacío ("Main Branch is not analyzed").
# pipefail: el exit code es el de docker, no el de tee.
if docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  --shm-size=1g \
  -e SONAR_HOST_URL="http://host.docker.internal:${PORT}" \
  -e SONAR_TOKEN="${TOKEN}" \
  -e SONAR_SCANNER_JAVA_OPTS="-Xmx2G" \
  -v "${REPO_ROOT}:/usr/src" \
  -w /usr/src \
  "${SCANNER_IMAGE}" \
  -Dsonar.projectKey="${PROJECT_KEY}" \
  -Dsonar.projectName="${PROJECT_NAME}" \
  -Dsonar.sources=. \
  -Dsonar.working.directory=/tmp/scannerwork \
  -Dsonar.javascript.node.maxspace=4096 \
  -Dsonar.exclusions="${EXCLUSIONS}" \
  2>&1 | tee "${SCAN_LOG}"
then
  log "sonar-scanner terminó OK."
else
  write_status scan_failed "El scanner falló (a menudo RAM en JS/TS). Ver ${SCAN_LOG}. Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
  log "ERROR: sonar-scanner falló. Revisá ${SCAN_LOG}"
  log "Dashboard (puede seguir vacío): ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
  exit 1
fi

log "Esperando a que SonarQube termine de procesar el análisis..."
sleep 5
for i in $(seq 1 60); do
  PENDING="$(curl -s -u "${TOKEN}:" \
    "${SONAR_URL}/api/ce/activity?component=${PROJECT_KEY}&status=IN_PROGRESS,PENDING" \
    | jq '.tasks | length' 2>/dev/null || echo "1")"
  if [ "$PENDING" = "0" ]; then
    log "Compute Engine idle."
    break
  fi
  sleep 5
  if [ "$i" -eq 60 ]; then
    log "AVISO: timeout esperando Compute Engine; se exportan métricas igual."
  fi
done

MEASURES="$(curl -s -u "${TOKEN}:" \
  "${SONAR_URL}/api/measures/component?component=${PROJECT_KEY}&metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,coverage,duplicated_lines_density")"
QG="$(curl -s -u "${TOKEN}:" \
  "${SONAR_URL}/api/qualitygates/project_status?projectKey=${PROJECT_KEY}")"

SUMMARY_PATH="${OUTPUT_DIR}/sonarqube-summary.json"
python3 - "$MEASURES" "$QG" "$SUMMARY_PATH" "$SONAR_URL" "$PROJECT_KEY" <<'PY'
import json, sys
from pathlib import Path

measures_raw, qg_raw, out_path, sonar_url, project_key = sys.argv[1:6]

def metric(data, key, default="0"):
    try:
        for m in data.get("component", {}).get("measures", []):
            if m.get("metric") == key:
                val = m.get("value", default)
                return default if val in (None, "") else val
    except (AttributeError, TypeError):
        pass
    return default

try:
    measures = json.loads(measures_raw)
except json.JSONDecodeError:
    measures = {}
try:
    qg = json.loads(qg_raw)
except json.JSONDecodeError:
    qg = {}

status = (qg.get("projectStatus") or {}).get("status") or "NONE"
summary = {
    "bugs": int(float(metric(measures, "bugs", "0"))),
    "vulnerabilities": int(float(metric(measures, "vulnerabilities", "0"))),
    "code_smells": int(float(metric(measures, "code_smells", "0"))),
    "security_hotspots": int(float(metric(measures, "security_hotspots", "0"))),
    "quality_gate": status,
    "coverage": metric(measures, "coverage", "n/a"),
    "duplicated_lines_density": metric(measures, "duplicated_lines_density", "n/a"),
    "dashboard_url": f"{sonar_url}/dashboard?id={project_key}",
}
Path(out_path).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(f"[run-sonarqube] escrito {out_path}")
PY

QG_STATUS="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('quality_gate','NONE'))" "${SUMMARY_PATH}" 2>/dev/null || echo "NONE")"
if [ "$QG_STATUS" = "NONE" ]; then
  write_status scan_failed "El scanner corrió pero Sonar no tiene análisis (quality gate NONE). Ver ${SCAN_LOG}. ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
  log "AVISO: quality gate NONE — el dashboard puede seguir vacío. Log: ${SCAN_LOG}"
  exit 1
fi
write_status up "Análisis listo. ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
log "Listo. Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"
