#!/usr/bin/env bash
# run-zap.sh — OWASP ZAP contra una URL web o una API.
#
# Compat:
#   ./run-zap.sh <target_url> <baseline|active> <output_dir>
#     → zap-dast-report.{html,json}
#
# Flags:
#   ./run-zap.sh --url URL --kind web|api [--scan-type baseline|active] \
#                [--output-dir DIR] [--openapi FILE|URL] [--prefix NAME]
#
# API + OpenAPI → zap-api-scan.py. API sin spec → baseline (más débil).
# localhost se reescribe a host.docker.internal.

set -euo pipefail

TARGET_URL=""
SCAN_TYPE="baseline"
OUTPUT_DIR="security-reports"
KIND="web"
OPENAPI=""
PREFIX=""
IMAGE="${ZAP_DOCKER_IMAGE:-zaproxy/zap-stable}"

log() { echo "[run-zap] $*" >&2; }

usage() {
  echo "Uso: run-zap.sh <url> [baseline|active] [output_dir]" >&2
  echo "  o: run-zap.sh --url URL --kind web|api [--openapi FILE] [--prefix NAME]" >&2
  exit 2
}

if [ $# -gt 0 ] && [[ "$1" == http://* || "$1" == https://* ]]; then
  TARGET_URL="$1"
  SCAN_TYPE="${2:-baseline}"
  OUTPUT_DIR="${3:-security-reports}"
  PREFIX="zap-dast-report"
else
  while [ $# -gt 0 ]; do
    case "$1" in
      --url) TARGET_URL="${2:-}"; shift ;;
      --kind) KIND="${2:-web}"; shift ;;
      --scan-type) SCAN_TYPE="${2:-baseline}"; shift ;;
      --output-dir) OUTPUT_DIR="${2:-security-reports}"; shift ;;
      --openapi) OPENAPI="${2:-}"; shift ;;
      --prefix) PREFIX="${2:-}"; shift ;;
      -h|--help) usage ;;
      *) log "argumento desconocido: $1"; usage ;;
    esac
    shift
  done
fi

if [ -z "$TARGET_URL" ] && [ -z "$OPENAPI" ]; then
  log "Falta --url o --openapi."
  usage
fi

if [ -z "$PREFIX" ]; then
  if [ "$KIND" = "api" ]; then
    PREFIX="zap-dast-api"
  elif [ "$KIND" = "web" ]; then
    PREFIX="zap-dast-web"
  else
    PREFIX="zap-dast-report"
  fi
fi

mkdir -p "${OUTPUT_DIR}"
ABS_OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  log "ERROR: Docker no está instalado."
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  log "ERROR: el daemon de Docker no está corriendo. En macOS: open -a Docker"
  exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "Descargando ${IMAGE} (puede tardar, ~1GB)..."
  docker pull "$IMAGE" >&2
fi

rewrite_host() {
  printf '%s' "$1" | sed -E 's#://(localhost|127\.0\.0\.1)(:|/)#://host.docker.internal\2#'
}

check_http() {
  local url="$1"
  local code
  code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "${url}" || echo "000")"
  if [ "$code" = "000" ]; then
    log "ERROR: el target no responde (${url}). Tiene que estar corriendo. Localhost vale."
    return 1
  fi
  log "Target responde HTTP ${code}."
}

ZAP_TARGET=""
ZAP_SCRIPT=""
ZAP_EXTRA=()

if [ -n "$OPENAPI" ] && [ "$KIND" = "api" ]; then
  ZAP_SCRIPT="zap-api-scan.py"
  if [[ "$OPENAPI" == http://* || "$OPENAPI" == https://* ]]; then
    check_http "$OPENAPI" || exit 1
    ZAP_TARGET="$(rewrite_host "$OPENAPI")"
  else
    if [ ! -f "$OPENAPI" ]; then
      log "ERROR: no existe el spec OpenAPI: ${OPENAPI}"
      exit 1
    fi
    SPEC_NAME="$(basename "$OPENAPI")"
    cp "$OPENAPI" "${ABS_OUTPUT_DIR}/${SPEC_NAME}"
    ZAP_TARGET="/zap/wrk/${SPEC_NAME}"
  fi
  FMT="openapi"
  case "${OPENAPI##*.}" in
    json|yaml|yml)
      base="$(basename "$OPENAPI" | tr '[:upper:]' '[:lower:]')"
      if [[ "$base" == swagger* ]]; then FMT="swagger"; fi
      ;;
  esac
  ZAP_EXTRA=(-f "$FMT")
  log "API scan con spec ${OPENAPI} (formato ${FMT})."
elif [ -n "$TARGET_URL" ]; then
  check_http "$TARGET_URL" || exit 1
  ZAP_TARGET="$(rewrite_host "$TARGET_URL")"
  if [ "$ZAP_TARGET" != "$TARGET_URL" ]; then
    log "Reescrito para Docker: ${TARGET_URL} → ${ZAP_TARGET}"
  fi
  if [ "$KIND" = "api" ]; then
    log "API sin OpenAPI: baseline (cobertura más débil que zap-api-scan)."
  fi
  if [ "$SCAN_TYPE" = "active" ]; then
    ZAP_SCRIPT="zap-full-scan.py"
    log "ADVERTENCIA: active scan envía payloads de ataque reales."
  else
    ZAP_SCRIPT="zap-baseline.py"
  fi
else
  log "ERROR: API scan requiere --openapi o --url."
  exit 1
fi

log "Kind=${KIND} script=${ZAP_SCRIPT} target=${ZAP_TARGET} prefix=${PREFIX}"
if [ -n "$TARGET_URL" ] && [ "$ZAP_TARGET" != "$TARGET_URL" ]; then
  log "ZAP corre DENTRO de Docker. ${ZAP_TARGET} ES tu proceso en la Mac (${TARGET_URL})."
  log "No está escaneando otro server: host.docker.internal = esta máquina, no un contenedor."
fi

docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "${ABS_OUTPUT_DIR}:/zap/wrk/:rw" \
  -t "${IMAGE}" \
  ${ZAP_SCRIPT} \
  -t "${ZAP_TARGET}" \
  "${ZAP_EXTRA[@]+"${ZAP_EXTRA[@]}"}" \
  -r "${PREFIX}.html" \
  -J "${PREFIX}.json" \
  -I \
  || log "ZAP retornó código distinto de 0 (normal si encontró alertas)."

# Los reportes de ZAP quedan con host.docker.internal. Para humanos es localhost.
if [ -n "$TARGET_URL" ]; then
  python3 - "$ABS_OUTPUT_DIR" "$PREFIX" <<'PY'
import sys
from pathlib import Path
out, prefix = Path(sys.argv[1]), sys.argv[2]
for ext in (".json", ".html"):
    p = out / f"{prefix}{ext}"
    if p.is_file():
        text = p.read_text(encoding="utf-8", errors="replace")
        p.write_text(
            text.replace("host.docker.internal", "localhost").replace("127.0.0.1", "localhost"),
            encoding="utf-8",
        )
print(f"[run-zap] reportes reescritos a localhost: {prefix}.{{html,json}}", file=sys.stderr)
PY
fi

log "Reportes: ${OUTPUT_DIR}/${PREFIX}.{html,json} (URLs como localhost — es tu API/web en la Mac)"
