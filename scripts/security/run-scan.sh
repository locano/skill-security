#!/usr/bin/env bash
# run-scan.sh — Orquestador con progreso por fases.
#
#   ./run-scan.sh --project-name "Mi app" [--project-key key] \
#     [--web-url URL] [--api-url URL] [--target-url URL] \
#     [--openapi FILE] [--scan-type baseline|active] \
#     [--output-dir security-reports] [--port 9000]
#
# --target-url = un solo target (compat). Sin URL, ZAP se omite (SAST válido).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EXAMPLE_CONFIG="${PLUGIN_ROOT}/security-reports/security.config.example.yml"

PROJECT_NAME=""
PROJECT_KEY=""
TARGET_URL=""
WEB_URL=""
API_URL=""
OPENAPI=""
SCAN_TYPE="baseline"
OUTPUT_DIR="security-reports"
PORT="9000"

usage() {
  echo "Uso: run-scan.sh --project-name NAME [--web-url URL] [--api-url URL] [--target-url URL] [--openapi FILE] [--scan-type baseline|active]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --project-name) PROJECT_NAME="${2:-}"; shift ;;
    --project-key) PROJECT_KEY="${2:-}"; shift ;;
    --target-url) TARGET_URL="${2:-}"; shift ;;
    --web-url) WEB_URL="${2:-}"; shift ;;
    --api-url) API_URL="${2:-}"; shift ;;
    --openapi) OPENAPI="${2:-}"; shift ;;
    --scan-type) SCAN_TYPE="${2:-baseline}"; shift ;;
    --output-dir) OUTPUT_DIR="${2:-security-reports}"; shift ;;
    --port) PORT="${2:-9000}"; shift ;;
    -h|--help) usage ;;
    *) echo "[run-scan] argumento desconocido: $1" >&2; usage ;;
  esac
  shift
done

log() { echo "[run-scan] $*" >&2; }
phase() {
  echo "" >&2
  echo "=== [$1] $2 ===" >&2
}

if [ -z "$PROJECT_NAME" ]; then
  echo "[run-scan] Falta --project-name." >&2
  usage
fi

if [ -z "$PROJECT_KEY" ]; then
  PROJECT_KEY="$(printf '%s' "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
  [ -n "$PROJECT_KEY" ] || PROJECT_KEY="security-scan"
fi

if [ -z "$WEB_URL" ] && [ -z "$API_URL" ] && [ -n "$TARGET_URL" ]; then
  WEB_URL="$TARGET_URL"
fi

HAS_DAST=0
if [ -n "$WEB_URL" ] || [ -n "$API_URL" ] || [ -n "$OPENAPI" ]; then
  HAS_DAST=1
fi

mkdir -p "${OUTPUT_DIR}"
export SECURITY_OUTPUT_DIR="${OUTPUT_DIR}"
SONAR_DASHBOARD="http://localhost:${PORT}/dashboard?id=${PROJECT_KEY}"

CONFIG_PATH="${OUTPUT_DIR}/security.config.yml"
if [ ! -f "$CONFIG_PATH" ]; then
  if [ -f "$EXAMPLE_CONFIG" ]; then
    cp "$EXAMPLE_CONFIG" "$CONFIG_PATH"
  else
    printf 'project: {}\nbranding: {}\nzap: {}\noutput: {}\n' > "$CONFIG_PATH"
  fi
fi

python3 - "$CONFIG_PATH" "$PROJECT_NAME" "$PROJECT_KEY" "$TARGET_URL" "$WEB_URL" "$API_URL" "$OPENAPI" "$SCAN_TYPE" "$OUTPUT_DIR" <<'PY'
import sys
from pathlib import Path
path, name, key, target, web, api, openapi, scan_type, out_dir = sys.argv[1:10]
try:
    import yaml
except ImportError:
    sys.exit(0)
cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
cfg.setdefault("project", {})
cfg["project"]["name"] = name
cfg["project"]["key"] = key
cfg.setdefault("zap", {})
cfg["zap"]["target_url"] = target or web or api
cfg["zap"]["web_url"] = web
cfg["zap"]["api_url"] = api
cfg["zap"]["openapi"] = openapi
cfg["zap"]["scan_type"] = scan_type
cfg["zap"]["enabled"] = bool(web or api or openapi)
cfg.setdefault("output", {})
cfg["output"]["dir"] = out_dir
cfg["output"].setdefault("report_filename", "security-report-completo.html")
Path(path).write_text(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True), encoding="utf-8")
PY

phase "1/6" "Inventario + preflight (puede bajar imágenes ~1GB)"
python3 "${SCRIPT_DIR}/collect-inventory.py" "${OUTPUT_DIR}" || log "Inventario falló; se sigue."

if [ -z "$OPENAPI" ] && [ -f "${OUTPUT_DIR}/inventory.json" ]; then
  DETECTED="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print((d.get('openapi') or [''])[0])" "${OUTPUT_DIR}/inventory.json" 2>/dev/null || true)"
  if [ -n "$DETECTED" ]; then
    OPENAPI="$DETECTED"
    log "OpenAPI detectado: ${OPENAPI}"
  fi
fi

python3 - "$OUTPUT_DIR" "$HAS_DAST" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1]) / "inventory.json"
if p.exists():
    data = json.loads(p.read_text(encoding="utf-8"))
    data["dast_applies"] = sys.argv[2] == "1"
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

PREREQ_ARGS=("${OUTPUT_DIR}")
if [ "$HAS_DAST" -eq 1 ]; then
  PREREQ_ARGS+=(--with-zap)
fi
PREREQ_RC=0
bash "${SCRIPT_DIR}/check-prereqs.sh" "${PREREQ_ARGS[@]}" || PREREQ_RC=$?
if [ "$PREREQ_RC" -eq 1 ]; then
  log "Preflight falló (falta python3). Abortando."
  exit 1
fi

phase "2/6" "SAST + SCA local (Bandit / pip-audit / npm audit)"
bash "${SCRIPT_DIR}/run-sast-sca.sh" "${OUTPUT_DIR}"

phase "3/6" "SonarQube — dashboard ${SONAR_DASHBOARD} (primer arranque 1–2 min)"
log "Si el scan falla, abrí igual: ${SONAR_DASHBOARD}"
SONAR_READY="$(python3 -c "import json,sys; p=json.load(open(sys.argv[1])); print('true' if p.get('sonar_ready') else 'false')" "${OUTPUT_DIR}/prereqs.json" 2>/dev/null || echo "false")"
if [ "$SONAR_READY" = "true" ]; then
  bash "${SCRIPT_DIR}/run-sonarqube.sh" "${PROJECT_KEY}" "${PROJECT_NAME}" "${OUTPUT_DIR}" "${PORT}" \
    || log "SonarQube falló. Dashboard: ${SONAR_DASHBOARD}"
else
  python3 "${SCRIPT_DIR}/write-sonar-status.py" "${OUTPUT_DIR}" images_missing \
    "Docker/imágenes no listos. URL prevista: ${SONAR_DASHBOARD}" \
    "http://localhost:${PORT}" "${PROJECT_KEY}" || true
  log "SonarQube omitido. URL prevista: ${SONAR_DASHBOARD}"
fi

phase "4/6" "DAST OWASP ZAP (solo si hay URL HTTP)"
ZAP_READY="$(python3 -c "import json,sys; p=json.load(open(sys.argv[1])); print('true' if p.get('zap_ready') else 'false')" "${OUTPUT_DIR}/prereqs.json" 2>/dev/null || echo "false")"
if [ "$HAS_DAST" -eq 0 ]; then
  log "ZAP omitido: no hay --web-url / --api-url / --target-url. SAST sigue siendo válido."
elif [ "$ZAP_READY" != "true" ]; then
  log "ZAP omitido: Docker/imagen no listos."
else
  if [ -n "$WEB_URL" ] && [ -n "$API_URL" ]; then
    log "ZAP web → ${WEB_URL} (varios minutos)..."
    bash "${SCRIPT_DIR}/run-zap.sh" --url "${WEB_URL}" --kind web --scan-type "${SCAN_TYPE}" \
      --output-dir "${OUTPUT_DIR}" --prefix zap-dast-web \
      || log "ZAP web falló; se sigue."
    log "ZAP API → ${API_URL}..."
    API_ARGS=(--url "${API_URL}" --kind api --scan-type "${SCAN_TYPE}" --output-dir "${OUTPUT_DIR}" --prefix zap-dast-api)
    if [ -n "$OPENAPI" ]; then API_ARGS+=(--openapi "${OPENAPI}"); fi
    bash "${SCRIPT_DIR}/run-zap.sh" "${API_ARGS[@]}" || log "ZAP API falló; se sigue."
  elif [ -n "$API_URL" ] || [ -n "$OPENAPI" ]; then
    API_ARGS=(--kind api --scan-type "${SCAN_TYPE}" --output-dir "${OUTPUT_DIR}")
    if [ -n "$API_URL" ]; then API_ARGS+=(--url "${API_URL}"); fi
    if [ -n "$OPENAPI" ]; then API_ARGS+=(--openapi "${OPENAPI}"); fi
    if [ -z "$WEB_URL" ] && [ -n "$TARGET_URL" ] && [ -z "$API_URL" ]; then
      bash "${SCRIPT_DIR}/run-zap.sh" "${TARGET_URL}" "${SCAN_TYPE}" "${OUTPUT_DIR}" || log "ZAP falló."
    else
      API_ARGS+=(--prefix zap-dast-api)
      bash "${SCRIPT_DIR}/run-zap.sh" "${API_ARGS[@]}" || log "ZAP API falló."
    fi
  else
    # una sola URL web (incluye --target-url compat → zap-dast-report.json)
    if [ -n "$TARGET_URL" ] && [ "$WEB_URL" = "$TARGET_URL" ]; then
      bash "${SCRIPT_DIR}/run-zap.sh" "${TARGET_URL}" "${SCAN_TYPE}" "${OUTPUT_DIR}" \
        || log "ZAP falló; se sigue."
    else
      bash "${SCRIPT_DIR}/run-zap.sh" --url "${WEB_URL}" --kind web --scan-type "${SCAN_TYPE}" \
        --output-dir "${OUTPUT_DIR}" --prefix zap-dast-web \
        || log "ZAP web falló; se sigue."
    fi
  fi
fi

phase "5/6" "Mapeo OWASP Top 10 / API Top 10"
python3 "${SCRIPT_DIR}/map-owasp.py" "${OUTPUT_DIR}" || log "map-owasp falló."

phase "6/6" "Reporte HTML"
python3 "${SCRIPT_DIR}/generate-report-template.py" "${OUTPUT_DIR}"

echo "" >&2
log "Listo. HTML: ${OUTPUT_DIR}/security-report-completo.html"
if [ -f "${OUTPUT_DIR}/.sonar-admin" ] && [ -s "${OUTPUT_DIR}/.sonar-admin" ]; then
  SONAR_PASS="$(cat "${OUTPUT_DIR}/.sonar-admin")"
else
  SONAR_PASS="Security_Scan_$(date +%Y)!"
fi
log "────────────────────────────────────────"
log "SonarQube: ${SONAR_DASHBOARD}"
log "Usuario:   admin"
log "Password:  ${SONAR_PASS}"
log "Archivo:   ${OUTPUT_DIR}/.sonar-admin"
log "────────────────────────────────────────"
