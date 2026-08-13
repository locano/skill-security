#!/usr/bin/env bash
# run-zap.sh — Ejecuta OWASP ZAP (baseline o active scan) contra una URL target
# usando el contenedor oficial zaproxy/zap-stable, y exporta reporte HTML + JSON.
#
# Uso:
#   ./run-zap.sh <target_url> <scan_type: baseline|active> <output_dir>
#
# Requiere: docker

set -euo pipefail

TARGET_URL="${1:?Uso: run-zap.sh <target_url> <baseline|active> <output_dir>}"
SCAN_TYPE="${2:-baseline}"
OUTPUT_DIR="${3:-security-reports}"
IMAGE="zaproxy/zap-stable"

log() { echo "[run-zap] $*" >&2; }

mkdir -p "${OUTPUT_DIR}"
ABS_OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

log "Target: ${TARGET_URL}"
log "Tipo de scan: ${SCAN_TYPE}"

if [ "$SCAN_TYPE" = "active" ]; then
  SCRIPT="zap-full-scan.py"
  log "ADVERTENCIA: active scan envía payloads de ataque reales al target."
  log "Solo ejecutar contra ambientes dev/staging con autorización explícita."
else
  SCRIPT="zap-baseline.py"
fi

docker run --rm \
  -v "${ABS_OUTPUT_DIR}:/zap/wrk/:rw" \
  -t "${IMAGE}" \
  ${SCRIPT} \
  -t "${TARGET_URL}" \
  -r zap-dast-report.html \
  -J zap-dast-report.json \
  -I \
  || log "ZAP retornó código distinto de 0 (normal si encontró alertas)."

log "Reportes generados en ${OUTPUT_DIR}/zap-dast-report.{html,json}"
