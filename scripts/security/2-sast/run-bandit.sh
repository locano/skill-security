#!/usr/bin/env bash
# run-bandit.sh — SAST de código Python con Bandit.
#
# Analiza el código fuente buscando patrones inseguros (eval, subprocess con
# shell, credenciales hardcodeadas, crypto débil). No ejecuta nada del proyecto.
#
# Uso: ./run-bandit.sh [output_dir]
# Salida: <output_dir>/bandit-report.json
#
# Requiere: python3. Si Bandit no está instalado, lo baja en un venv temporal.

set -uo pipefail

OUTPUT_DIR="${1:-security-reports}"
mkdir -p "${OUTPUT_DIR}"

log() { echo "[run-bandit] $*" >&2; }

if ! find . -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv*/*" | grep -q .; then
  log "Sin archivos Python: nada que analizar."
  exit 0
fi

log "Python detectado — ejecutando Bandit..."
if ! command -v bandit >/dev/null 2>&1; then
  log "Bandit no instalado, instalando en venv temporal..."
  python3 -m venv /tmp/.bandit-venv 2>/dev/null || true
  # shellcheck disable=SC1091
  source /tmp/.bandit-venv/bin/activate
  pip install -q bandit
fi

bandit -r . -f json -o "${OUTPUT_DIR}/bandit-report.json" \
  -x "*/node_modules/*,*/.venv*/*,*/test/*,*/tests/*" || true
log "-> ${OUTPUT_DIR}/bandit-report.json"
